from app.tasks.contact_task import send_contact_email

class ContactService:
    @staticmethod
    def send_contact(fullname: str, email: str, message: str):
        send_contact_email.delay(fullname, email, message)
