from sqlalchemy.orm import Session
from app.models.scan import Scan, ScanStatus
from typing import List

def get_scans_for_user(db: Session, user_id: int) -> List[Scan]:
    return db.query(Scan).filter(Scan.user_id == user_id).all()


def create_scan(db: Session, user_id: int, target: str) -> Scan:
    scan = Scan(user_id=user_id, domain=target, status=ScanStatus.pending)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def update_scan_status(db: Session, scan_id: int, status: ScanStatus, pdf_path: str = None):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return None
    scan.status = status
    if pdf_path:
        scan.pdf_path = pdf_path
    db.commit()
    db.refresh(scan)
    return scan
