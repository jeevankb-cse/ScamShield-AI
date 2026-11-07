from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app.extensions import db
from app.models.scan import Scan, ScanHistory
from app.models.scan_result import ScanResult
from app.utils.validators import validate_password_strength

history_bp = Blueprint("history", __name__)


@history_bp.route("/history")
@login_required
def history_page():
    """Searchable, filterable scan history for authenticated user."""
    scan_type = request.args.get("type", "").strip()
    risk_band = request.args.get("risk", "").strip()
    search = request.args.get("q", "").strip()

    query = (
        db.session.query(Scan)
        .join(ScanResult, Scan.id == ScanResult.scan_id)
        .filter(Scan.user_id == current_user.id)
    )

    if scan_type:
        query = query.filter(Scan.scan_type == scan_type)

    if risk_band:
        query = query.filter(ScanResult.risk_level == risk_band)

    if search:
        query = query.filter(
            (Scan.input_preview.ilike(f"%{search}%")) |
            (ScanResult.predicted_category.ilike(f"%{search}%"))
        )

    scans = query.order_by(Scan.created_at.desc()).all()

    return render_template(
        "history.html",
        scans=scans,
        active_type=scan_type,
        active_risk=risk_band,
        search_query=search
    )


@history_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """User profile and credential security settings."""
    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        if not current_user.check_password(current_pw):
            flash("Incorrect current password.", "danger")
            return redirect(url_for("history.profile"))

        if new_pw != confirm_pw:
            flash("New passwords do not match.", "danger")
            return redirect(url_for("history.profile"))

        valid, err = validate_password_strength(new_pw)
        if not valid:
            flash(err, "danger")
            return redirect(url_for("history.profile"))

        try:
            current_user.set_password(new_pw)
            db.session.commit()
            flash("Password updated successfully.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Update failed: {str(e)}", "danger")

        return redirect(url_for("history.profile"))

    # Summary metrics
    scan_count = Scan.query.filter_by(user_id=current_user.id).count()

    return render_template(
        "profile.html",
        user=current_user,
        scan_count=scan_count
    )
