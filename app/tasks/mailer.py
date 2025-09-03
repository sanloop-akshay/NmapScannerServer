# app/tasks/mailer.py
import os
from email.message import EmailMessage
import smtplib
from app.core.celery_app import celery_app

EMAIL_HOST = os.getenv("EMAIL_HOST")
APP_PASSWORD = os.getenv("APP_PASSWORD")
@celery_app.task(name="app.tasks.mailer.send_signup_otp_email")
def send_signup_otp_email(email: str, otp: str):
    print("Executing Celery task: send_signup_otp_email")
    try:
        if not EMAIL_HOST or not APP_PASSWORD:
            raise ValueError("EMAIL_HOST or APP_PASSWORD not set")

        msg = EmailMessage()
        msg["Subject"] = "Your Signup OTP"
        msg["From"] = EMAIL_HOST
        msg["To"] = email
        msg.set_content(f"Your OTP is: {otp}")

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_HOST, APP_PASSWORD)
            smtp.send_message(msg)

        print(f"OTP email sent to {email}")
        return True

    except Exception as e:
        print(f"Failed to send OTP email: {e}")
        return False
