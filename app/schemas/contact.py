from pydantic import BaseModel, EmailStr

class ContactRequest(BaseModel):
    fullname: str
    email: EmailStr
    message: str