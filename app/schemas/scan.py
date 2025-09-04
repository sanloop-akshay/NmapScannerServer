from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from app.models.scan import ScanStatus


class ScanCreate(BaseModel):
    target: str


class ScanResponse(BaseModel):
    id: int
    domain: str
    status: ScanStatus
    scanned_at: datetime
    pdf_path: Optional[str] = None

    class Config:
        orm_mode = True
        
class ScanDeleteResponse(BaseModel):
    detail: str