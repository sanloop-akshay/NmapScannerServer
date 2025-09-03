from pydantic import BaseModel, EmailStr, constr

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SignupRequest(BaseModel):
    fullname: constr(min_length=3, max_length=100)
    email: EmailStr
    password: constr(min_length=6, max_length=128)

class SignupResponse(BaseModel):
    message: str
    
    
class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp: constr(min_length=6, max_length=6)  

class OTPVerifyResponse(BaseModel):
    message: str