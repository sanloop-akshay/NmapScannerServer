# app/core/celery_app.py
import os
from celery import Celery
from dotenv import load_dotenv

load_dotenv()

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

celery_app = Celery(
    "worker",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
    include=[
        "app.tasks.mailer",  
        "app.tasks.scan_tasks", 
        "app.tasks.contact_task"
    ]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="Asia/Kolkata",
    enable_utc=True,
    task_track_started=True,
    result_expires=3600,
)

celery_app.conf.task_routes = {
    "app.tasks.otp_tasks.send_signup_otp_email": {"queue": "default"},
}