from fastapi import APIRouter, Depends, Request,HTTPException, status
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from app.core.config import SECRET_KEY, ALGORITHM
from app.core.database import get_db
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanResponse, ScanDeleteResponse
from app.services.scan_service import create_scan,get_scans_for_user
from app.tasks.scan_tasks import run_all_scans
from app.core.security import get_current_user
from typing import List
from app.services.scan_service import delete_scan
router = APIRouter(prefix="/scan", tags=["scan"])

@router.get("/", response_model=List[ScanResponse], status_code=status.HTTP_200_OK)
def list_user_scans(request: Request, db: Session = Depends(get_db)):
    user: User = get_current_user(request, db)

    scans = get_scans_for_user(db, user.id)
    if not scans:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No scans found for this user",
        )

    return scans

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


@router.delete("/{scan_id}", response_model=ScanDeleteResponse, status_code=status.HTTP_200_OK)
def delete_scan_request(scan_id: int, request: Request, db: Session = Depends(get_db)):
    user: User = get_current_user(request, db)

    try:
        delete_scan(db, scan_id, user.id)
    except HTTPException as e:
        raise e

    return {"detail": "Scan deleted successfully"}