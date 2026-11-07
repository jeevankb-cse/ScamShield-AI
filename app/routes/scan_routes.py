from pathlib import Path
from flask import Blueprint, render_template, request, jsonify, current_app, redirect, url_for
from flask_login import current_user

from app.extensions import db
from app.models.scan import Scan, ScanHistory
from app.models.scan_result import ScanResult, ScanEvidence
from app.services.text_analyzer import analyze_text_message
from app.services.email_analyzer import analyze_email_content
from app.services.url_analyzer import analyze_url_target
from app.services.image_analyzer import analyze_image_file
from app.services.invoice_analyzer import analyze_pdf_invoice
from app.utils.file_security import validate_upload, save_securely, safe_delete

scan_bp = Blueprint("scan", __name__)


def _save_scan_to_database(scan_type: str, result_dict: dict) -> int:
    """Helper to persist scan record, result, and associated evidence."""
    user_id = current_user.id if current_user.is_authenticated else None

    scan = Scan(
        user_id=user_id,
        scan_type=scan_type,
        input_preview=result_dict.get("input_preview", ""),
        status="completed"
    )
    db.session.add(scan)
    db.session.flush()

    sr = ScanResult(
        scan_id=scan.id,
        risk_score=result_dict.get("risk_score", 0),
        risk_level=result_dict.get("risk_level", "Low Risk"),
        predicted_category=result_dict.get("predicted_category", "Unknown"),
        model_version=result_dict.get("model_version", "v1.0.0"),
        confidence=result_dict.get("confidence", 0.0),
        explanation=result_dict.get("explanation", ""),
    )
    sr.set_recommendations_list(result_dict.get("recommendations", []))
    db.session.add(sr)
    db.session.flush()

    for ev in result_dict.get("evidence", []):
        sev = ev.get("severity", "medium")
        evidence_entry = ScanEvidence(
            scan_result_id=sr.id,
            evidence_type=ev.get("evidence_type", "general"),
            evidence_description=ev.get("evidence_description", ""),
            severity=sev
        )
        db.session.add(evidence_entry)

    history = ScanHistory(
        scan_id=scan.id,
        user_id=user_id,
        action_taken="scanned"
    )
    db.session.add(history)
    db.session.commit()

    return scan.id


@scan_bp.route("/scan")
def scan_page():
    """Scanner interface with tabbed inputs for all 5 scanner modules."""
    initial_tab = request.args.get("tab", "message")
    return render_template("scan.html", active_tab=initial_tab)


@scan_bp.route("/scan/<int:scan_id>")
def view_result(scan_id):
    """Detailed view for a specific scan result."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return render_template("errors/404.html", error="Scan result not found."), 404

    # Authorization: allow if public or if owner or if admin
    if scan.user_id is not None:
        if not current_user.is_authenticated or (current_user.id != scan.user_id and not current_user.is_admin()):
            return render_template("errors/403.html", error="You do not have permission to view this scan."), 403

    return render_template("scan_result.html", scan=scan, result=scan.result)


@scan_bp.route("/api/scan/text", methods=["POST"])
def api_scan_text():
    data = request.get_json(silent=True) or request.form
    text = data.get("text", "").strip()

    if not text:
        return jsonify({"success": False, "error": "Please provide message text to scan."}), 400

    analysis = analyze_text_message(text)
    if not analysis.get("success"):
        return jsonify(analysis), 400

    scan_id = _save_scan_to_database("message", analysis)
    analysis["scan_id"] = scan_id
    analysis["result_url"] = url_for("scan.view_result", scan_id=scan_id)
    return jsonify(analysis)


@scan_bp.route("/api/scan/email", methods=["POST"])
def api_scan_email():
    data = request.get_json(silent=True) or request.form
    sender = data.get("sender", "").strip()
    subject = data.get("subject", "").strip()
    body = data.get("body", "").strip()

    if not body and not subject:
        return jsonify({"success": False, "error": "Please provide email subject or body."}), 400

    analysis = analyze_email_content(sender, subject, body)
    if not analysis.get("success"):
        return jsonify(analysis), 400

    scan_id = _save_scan_to_database("email", analysis)
    analysis["scan_id"] = scan_id
    analysis["result_url"] = url_for("scan.view_result", scan_id=scan_id)
    return jsonify(analysis)


@scan_bp.route("/api/scan/url", methods=["POST"])
def api_scan_url():
    data = request.get_json(silent=True) or request.form
    url_input = data.get("url", "").strip()

    if not url_input:
        return jsonify({"success": False, "error": "Please provide a website URL."}), 400

    analysis = analyze_url_target(url_input)
    if not analysis.get("success"):
        return jsonify(analysis), 400

    scan_id = _save_scan_to_database("url", analysis)
    analysis["scan_id"] = scan_id
    analysis["result_url"] = url_for("scan.view_result", scan_id=scan_id)
    return jsonify(analysis)


@scan_bp.route("/api/scan/image", methods=["POST"])
def api_scan_image():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No image file uploaded."}), 400

    file = request.files["file"]
    valid, ext_or_err = validate_upload(file, allowed_types={"jpg", "jpeg", "png", "webp"})
    if not valid:
        return jsonify({"success": False, "error": ext_or_err}), 400

    upload_folder = Path(current_app.config["UPLOAD_FOLDER"])
    saved_path = save_securely(file, upload_folder, ext_or_err)

    try:
        analysis = analyze_image_file(saved_path)
    finally:
        # Delete temporary file immediately
        safe_delete(saved_path)

    if not analysis.get("success"):
        return jsonify(analysis), 400

    scan_id = _save_scan_to_database("image", analysis)
    analysis["scan_id"] = scan_id
    analysis["result_url"] = url_for("scan.view_result", scan_id=scan_id)
    return jsonify(analysis)


@scan_bp.route("/api/scan/pdf", methods=["POST"])
def api_scan_pdf():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No PDF invoice uploaded."}), 400

    file = request.files["file"]
    valid, ext_or_err = validate_upload(file, allowed_types={"pdf"})
    if not valid:
        return jsonify({"success": False, "error": ext_or_err}), 400

    upload_folder = Path(current_app.config["UPLOAD_FOLDER"])
    saved_path = save_securely(file, upload_folder, ext_or_err)

    comp_path = None
    if "comparison_file" in request.files and request.files["comparison_file"].filename != "":
        comp_file = request.files["comparison_file"]
        comp_valid, comp_ext = validate_upload(comp_file, allowed_types={"pdf"})
        if comp_valid:
            comp_path = save_securely(comp_file, upload_folder, comp_ext)

    try:
        analysis = analyze_pdf_invoice(saved_path, comp_path)
    finally:
        safe_delete(saved_path)
        if comp_path:
            safe_delete(comp_path)

    if not analysis.get("success"):
        return jsonify(analysis), 400

    scan_id = _save_scan_to_database("pdf_invoice", analysis)
    analysis["scan_id"] = scan_id
    analysis["result_url"] = url_for("scan.view_result", scan_id=scan_id)
    return jsonify(analysis)


@scan_bp.route("/api/scans/<int:scan_id>")
def api_get_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"success": False, "error": "Scan not found."}), 404

    if scan.user_id is not None:
        if not current_user.is_authenticated or (current_user.id != scan.user_id and not current_user.is_admin()):
            return jsonify({"success": False, "error": "Access unauthorized."}), 403

    return jsonify({"success": True, "scan": scan.to_dict()})
