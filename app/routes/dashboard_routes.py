from datetime import datetime, timedelta
from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user
from sqlalchemy import func

from app.extensions import db
from app.models.scan import Scan
from app.models.scan_result import ScanResult

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    """Public landing page showcasing platform capabilities."""
    total_scans_count = Scan.query.count()
    high_threats_count = ScanResult.query.filter(ScanResult.risk_score >= 60).count()
    return render_template(
        "index.html",
        total_scans=total_scans_count,
        high_threats=high_threats_count
    )


@dashboard_bp.route("/dashboard")
@login_required
def dashboard():
    """Authenticated user dashboard with analytics and scan controls."""
    # Base user query
    user_scans_query = Scan.query.filter_by(user_id=current_user.id)
    total_scans = user_scans_query.count()

    # Risk band counts
    results_query = (
        db.session.query(ScanResult)
        .join(Scan, ScanResult.scan_id == Scan.id)
        .filter(Scan.user_id == current_user.id)
    )

    high_risk_count = results_query.filter(ScanResult.risk_score >= 60).count()
    med_risk_count = results_query.filter(ScanResult.risk_score >= 30, ScanResult.risk_score < 60).count()
    low_risk_count = results_query.filter(ScanResult.risk_score < 30).count()

    # Recent scans (latest 8)
    recent_scans = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(8)
        .all()
    )

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        high_risk_count=high_risk_count,
        med_risk_count=med_risk_count,
        low_risk_count=low_risk_count,
        recent_scans=recent_scans
    )


@dashboard_bp.route("/api/dashboard/stats")
@login_required
def dashboard_stats():
    """JSON API providing aggregated metrics for Chart.js rendering."""
    # 1. Scam Category Distribution
    category_counts = (
        db.session.query(ScanResult.predicted_category, func.count(ScanResult.id))
        .join(Scan, ScanResult.scan_id == Scan.id)
        .filter(Scan.user_id == current_user.id)
        .group_by(ScanResult.predicted_category)
        .all()
    )
    categories = [c[0] for c in category_counts]
    category_values = [c[1] for c in category_counts]

    # 2. Scan Type Distribution
    type_counts = (
        db.session.query(Scan.scan_type, func.count(Scan.id))
        .filter(Scan.user_id == current_user.id)
        .group_by(Scan.scan_type)
        .all()
    )
    scan_types = [t[0].capitalize() for t in type_counts]
    type_values = [t[1] for t in type_counts]

    # 3. Last 7 Days Trend
    today = datetime.utcnow().date()
    days = [(today - timedelta(days=i)) for i in range(6, -1, -1)]
    day_labels = [d.strftime("%b %d") for d in days]
    day_counts = []

    for d in days:
        cnt = (
            Scan.query.filter(
                Scan.user_id == current_user.id,
                func.date(Scan.created_at) == d
            ).count()
        )
        day_counts.append(cnt)

    return jsonify({
        "categories": {
            "labels": categories or ["No Scans Yet"],
            "data": category_values or [0]
        },
        "scan_types": {
            "labels": scan_types or ["No Scans Yet"],
            "data": type_values or [0]
        },
        "weekly_trend": {
            "labels": day_labels,
            "data": day_counts
        }
    })


@dashboard_bp.route("/about")
def about():
    """About and Help documentation page."""
    return render_template("about.html")
