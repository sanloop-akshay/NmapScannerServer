from app.core.celery_app import celery_app
import time

@celery_app.task
def run_scan(domain: str):
    print(f"Starting scan for {domain}")
    time.sleep(5)  
    result = f"Scan completed for {domain}"
    print(result)
    return result
