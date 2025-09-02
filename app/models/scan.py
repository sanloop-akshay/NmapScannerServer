from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Enum, func
from sqlalchemy.orm import relationship
import enum
from app.core.database import Base

class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    domain = Column(String(255), nullable=False)
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())
    pdf_path = Column(String(500))
    status = Column(Enum(ScanStatus), default=ScanStatus.pending)

    user = relationship("User", back_populates="scans")
