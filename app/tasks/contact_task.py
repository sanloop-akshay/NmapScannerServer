import os
from email.message import EmailMessage
import smtplib
from app.core.celery_app import celery_app

EMAIL_HOST = os.getenv("EMAIL_HOST")
APP_PASSWORD = os.getenv("APP_PASSWORD")

@celery_app.task(name="app.tasks.contact_task.send_contact_email")
def send_contact_email(fullname: str, email: str, message: str):
    try:
        if not EMAIL_HOST or not APP_PASSWORD:
            raise ValueError("EMAIL_HOST or APP_PASSWORD not set")

        msg = EmailMessage()
        msg["Subject"] = f"New Contact Form Submission from {fullname}"
        msg["From"] = EMAIL_HOST
        msg["To"] = EMAIL_HOST
        msg.set_content(f"Name: {fullname}\nEmail: {email}\n\nMessage:\n{message}")

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_HOST, APP_PASSWORD)
            smtp.send_message(msg)
        return True

    except Exception as e:
        return False
