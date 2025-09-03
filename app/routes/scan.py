from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from app.core.config import SECRET_KEY, ALGORITHM
from app.core.database import get_db
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanResponse
from app.services.scan_service import create_scan
from app.tasks.scan_tasks import run_all_scans
from app.core.security import get_current_user

router = APIRouter(prefix="/scan", tags=["scan"])


@router.post("/", response_model=ScanResponse)
def create_scan_request(scan_data: ScanCreate, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)

    scan = create_scan(db, user.id, scan_data.target)
    run_all_scans.delay(scan_data.target, scan.id)

    return {
        "id": scan.id,
        "domain": scan.domain,
        "status": scan.status,
        "scanned_at": scan.scanned_at,
        "pdf_path": scan.pdf_path,
    }
