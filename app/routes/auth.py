from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from app.schemas.auth import LoginRequest,SignupRequest, SignupResponse,OTPVerifyRequest, OTPVerifyResponse
from app.core.database import get_db
from app.services.auth_service import authenticate_user, create_token_pair,signup_send_otp, verify_otp_and_create_user
from app.core.config import ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_MINUTES

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/login/", status_code=status.HTTP_200_OK)
def login(request: LoginRequest, response: Response, db: Session = Depends(get_db)):
    user = authenticate_user(db, request.email, request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    tokens = create_token_pair(user)
    response.set_cookie(
        key="access_token",
        value=tokens["access_token"],
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=False,
        samesite="lax"
    )
    response.set_cookie(
        key="refresh_token",
        value=tokens["refresh_token"],
        httponly=True,
        max_age=REFRESH_TOKEN_EXPIRE_MINUTES * 60,
        secure=False,
        samesite="lax"
    )
    return {"message": "Logged in successfully", "status_code": status.HTTP_200_OK}


@router.post("/signup/", response_model=SignupResponse)
def signup(request: SignupRequest, db: Session = Depends(get_db)):
    success, message = signup_send_otp(db, request.fullname, request.email, request.password)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)
    
    return {"message": message}


@router.post("/verify-otp/", response_model=OTPVerifyResponse)
def verify_otp(request: OTPVerifyRequest, db: Session = Depends(get_db)):
    success, message = verify_otp_and_create_user(db, request.email, request.otp)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)
    return {"message": message}

