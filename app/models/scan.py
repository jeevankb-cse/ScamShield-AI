from datetime import datetime
from app.extensions import db


class Scan(db.Model):
    """Represents a submitted scan request."""

    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    scan_type = db.Column(db.String(30), nullable=False, index=True)  # message, email, url, image, pdf_invoice
    input_preview = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default="completed")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    # Relationships
    result = db.relationship("ScanResult", backref="scan", uselist=False, cascade="all, delete-orphan")
    history_records = db.relationship("ScanHistory", backref="scan", cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "scan_type": self.scan_type,
            "input_preview": self.input_preview,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "result": self.result.to_dict() if self.result else None,
        }

    def __repr__(self) -> str:
        return f"<Scan {self.id} ({self.scan_type})>"


class ScanHistory(db.Model):
    """Tracks historical actions and scan access."""

    __tablename__ = "scan_history"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action_taken = db.Column(db.String(100), nullable=False, default="scanned")
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "user_id": self.user_id,
            "action_taken": self.action_taken,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


class AuditLog(db.Model):
    """Audit logging for critical user and system actions."""

    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "action": self.action,
            "details": self.details,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
