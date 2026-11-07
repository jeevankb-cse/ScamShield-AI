import json
from pathlib import Path
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app, abort
from flask_login import login_required, current_user

from app.extensions import db
from app.models.user import User
from app.models.scan import Scan, AuditLog
from app.models.scan_result import ScanResult

admin_bp = Blueprint("admin", __name__)


def admin_required(f):
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login", next=request.url))
        if not current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function


@admin_bp.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    """Admin management portal with audit logs and real model evaluation reports."""
    users = User.query.order_by(User.created_at.desc()).all()
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(30).all()

    total_users = User.query.count()
    total_scans = Scan.query.count()
    high_threats = ScanResult.query.filter(ScanResult.risk_score >= 60).count()

    # Read real saved model reports
    reports_dir = Path(current_app.config["ML_REPORTS_DIR"])

    text_report = None
    url_report = None
    email_report = None

    if (reports_dir / "text_model_report.json").exists():
        try:
            with open(reports_dir / "text_model_report.json") as f:
                text_report = json.load(f)
        except Exception:
            pass

    if (reports_dir / "url_model_report.json").exists():
        try:
            with open(reports_dir / "url_model_report.json") as f:
                url_report = json.load(f)
        except Exception:
            pass

    if (reports_dir / "email_model_report.json").exists():
        try:
            with open(reports_dir / "email_model_report.json") as f:
                email_report = json.load(f)
        except Exception:
            pass

    return render_template(
        "admin.html",
        users=users,
        audit_logs=audit_logs,
        total_users=total_users,
        total_scans=total_scans,
        high_threats=high_threats,
        text_report=text_report,
        url_report=url_report,
        email_report=email_report
    )


@admin_bp.route("/admin/user/<int:user_id>/toggle-status", methods=["POST"])
@login_required
@admin_required
def toggle_user_status(user_id):
    """Admin control to activate or deactivate user accounts."""
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    if user.id == current_user.id:
        flash("You cannot deactivate your own account.", "warning")
        return redirect(url_for("admin.admin_dashboard"))

    user.is_active = not user.is_active
    db.session.commit()

    flash(f"User {user.username} is now {'active' if user.is_active else 'deactivated'}.", "success")
    return redirect(url_for("admin.admin_dashboard"))
