from datetime import datetime, timedelta
from typing import Optional
from jose import jwt,JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from app.models.user import User
from app.core.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_MINUTES
from app.services.otp_service import generate_otp  
from app.core.security import hash_password,verify_password
from app.core.redis_client import redis_client 
from app.tasks.mailer import send_signup_otp_email


def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return None
    if not verify_password(password, user.password):
        return None
    return user

def create_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_token_pair(user: User):
    access_token = create_token({"sub": str(user.id)}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_token({"sub": str(user.id)}, timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "refresh_token": refresh_token}


def is_email_taken(db: Session, email: str) -> bool:
    return db.query(User).filter(User.email == email).first() is not None



def signup_send_otp(db: Session, fullname: str, email: str, password: str):
    if db.query(User).filter(User.email == email).first():
        return False, "Email already registered"
    otp = generate_otp()
    send_signup_otp_email.delay(email, otp)
    redis_key = f"user_signup:{email}"
    redis_client.hmset(redis_key, {
        "fullname": fullname,
        "email": email,
        "password": hash_password(password),
        "otp": otp
    })
    redis_client.expire(redis_key, 600)
    return True, "OTP sent successfully"



def verify_otp_and_create_user(db: Session, email: str, otp: str):
    redis_key = f"user_signup:{email}"
    temp_data = redis_client.hgetall(redis_key)
    if not temp_data:
        return False, "OTP expired or invalid"

    if temp_data.get("otp") != otp:
        return False, "Invalid OTP"

    user = User(
        fullname=temp_data["fullname"],
        email=temp_data["email"],
        password=temp_data["password"]  
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    redis_client.delete(redis_key)

    return True, "Signup successful"


def refresh_access_token(db: Session, refresh_token: str) -> str | None:
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            return None
    except JWTError:
        return None

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return None

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = create_token(
        data={"sub": str(user.id)},
        expires_delta=access_token_expires
    )
    return new_access_token