from app.core.celery_app import celery_app
import smtplib
from email.message import EmailMessage
from app.core.config import EMAIL_HOST, APP_PASSWORD

@celery_app.task
def send_signup_otp_email(to_email: str, otp: str):
    msg = EmailMessage()
    msg['Subject'] = 'Your Signup OTP'
    msg['From'] = EMAIL_HOST
    msg['To'] = to_email
    msg.set_content(f"Your OTP for signup is: {otp}")

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.login(EMAIL_HOST, APP_PASSWORD)
        server.send_message(msg)
