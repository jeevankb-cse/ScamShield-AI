from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db


class User(UserMixin, db.Model):
    """User account model supporting role-based access control."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user", index=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    scans = db.relationship("Scan", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    history_entries = db.relationship("ScanHistory", backref="user", lazy="dynamic")
    audit_logs = db.relationship("AuditLog", backref="user", lazy="dynamic")

    def set_password(self, password: str) -> None:
        """Hash and set user password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify candidate password against stored hash."""
        return check_password_hash(self.password_hash, password)

    def is_admin(self) -> bool:
        """Check if user has administrative privileges."""
        return self.role.lower() == "admin"

    def to_dict(self) -> dict:
        """Return serializable representation of user."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.role})>"
