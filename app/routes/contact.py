from fastapi import APIRouter, Depends, HTTPException, status
from app.schemas.contact import ContactRequest
from app.services.contact_service import ContactService

router = APIRouter(
    prefix="/support",
    tags=["Support"]
)

@router.post("/contact/", status_code=status.HTTP_202_ACCEPTED)
def submit_contact_form(contact: ContactRequest):
    try:
        ContactService.send_contact(
            fullname=contact.fullname,
            email=contact.email,
            message=contact.message
        )
        return {"detail": "Your message has been received. We will get back to you shortly."}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to submit contact form: {str(e)}"
        )
