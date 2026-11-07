import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from flask import Flask, render_template, jsonify
from sqlalchemy.exc import OperationalError

from config import Config
from app.extensions import db, login_manager


def create_app(config_class=Config):
    """Application factory for ScamShield AI."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure upload and log folders exist
    upload_path = Path(app.config["UPLOAD_FOLDER"])
    upload_path.mkdir(parents=True, exist_ok=True)
    logs_path = Path(app.config["LOGS_DIR"])
    logs_path.mkdir(parents=True, exist_ok=True)

    # Configure Logging
    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s in %(module)s: %(message)s"
    )
    file_handler = RotatingFileHandler(
        logs_path / "scamshield.log", maxBytes=10 * 1024 * 1024, backupCount=5
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)

    # Initialize Extensions
    db.init_app(app)
    login_manager.init_app(app)

    from app.models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(User, int(user_id))
        except Exception:
            return None

    # Handle Database Connection and Table Creation
    with app.app_context():
        try:
            # Test database connectivity
            db.engine.connect()
            db.create_all()
            _seed_initial_defaults(app)
            app.logger.info("Successfully connected to primary database.")
        except Exception as e:
            app.logger.warning(
                f"Primary database connection failed ({e}). Attempting fallback to SQLite."
            )
            app.config["SQLALCHEMY_DATABASE_URI"] = app.config["FALLBACK_DATABASE_URI"]
            # Reconnect with fallback
            db.engine.dispose()
            try:
                db.create_all()
                _seed_initial_defaults(app)
                app.logger.info("Connected to fallback SQLite database.")
            except Exception as fe:
                app.logger.error(f"Failed to initialize fallback database: {fe}")

    # Register Blueprints
    from app.routes.auth_routes import auth_bp
    from app.routes.dashboard_routes import dashboard_bp
    from app.routes.scan_routes import scan_bp
    from app.routes.history_routes import history_bp
    from app.routes.admin_routes import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(admin_bp)

    # Register Error Handlers
    _register_error_handlers(app)

    # Context Processors
    @app.context_processor
    def inject_global_vars():
        return {
            "app_name": "ScamShield AI",
            "version": "1.0.0",
        }

    # Security Headers
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    return app


def _seed_initial_defaults(app):
    """Ensure baseline admin and demo user exist if database is freshly initialized."""
    from app.models.user import User
    from app.models.scan import Scan, ScanHistory, AuditLog
    from app.models.scan_result import ScanResult, ScanEvidence

    try:
        if not User.query.filter_by(username="admin").first():
            admin = User(
                username="admin",
                email="admin@scamshield.ai",
                role="admin",
                is_active=True,
            )
            admin.set_password("Admin@123")
            db.session.add(admin)

        if not User.query.filter_by(username="user").first():
            demo_user = User(
                username="user",
                email="demo@scamshield.ai",
                role="user",
                is_active=True,
            )
            demo_user.set_password("User@123")
            db.session.add(demo_user)

        db.session.commit()

        # Seed sample scans if empty for rich initial dashboard
        if Scan.query.count() == 0:
            user_obj = User.query.filter_by(username="user").first()
            uid = user_obj.id if user_obj else None

            sample_scans = [
                (
                    "message",
                    "Dear customer, your SBI account 4819 is blocked due to missing PAN. Click http://sbi-pan-update.in to verify immediately.",
                    94,
                    "Very High Risk",
                    "Fake KYC updates",
                    "High probability banking phishing attempt impersonating State Bank of India (SBI) requesting urgent PAN verification via suspicious external domain.",
                    ["Do NOT click the embedded link.", "Block and report this number to 1930 or sbi.co.in.", "Banks never send unverified third-party links for KYC."],
                    [("impersonation", "Impersonates State Bank of India (SBI)", "critical"), ("url", "Suspicious domain http://sbi-pan-update.in", "critical")]
                ),
                (
                    "email",
                    "Subject: Income Tax Refund Notice 2026 - Action Required within 24 hours to claim Rs 42,850",
                    88,
                    "Very High Risk",
                    "Refund scams",
                    "Impersonates Income Tax Department offering fraudulent tax refund with artificial 24-hour urgency deadline to extract banking credentials.",
                    ["Never share banking credentials for refunds.", "Verify legitimate refunds only on incometax.gov.in.", "Report phishing email to incident@cert-in.org.in."],
                    [("impersonation", "Impersonates Government Tax Authority", "critical"), ("urgency", "Artificial 24-hour deadline trigger", "high")]
                ),
                (
                    "url",
                    "http://192.168.1.1/paytm-kyc-approval/login.php",
                    92,
                    "Very High Risk",
                    "Malicious URLs",
                    "Suspicious raw IP address hostname disguised as Paytm KYC portal with suspicious URL path keywords.",
                    ["Do NOT visit or input login credentials.", "Report malicious IP to national cybercrime portal.", "Always access Paytm exclusively via official app or paytm.com."],
                    [("url_ip", "Raw IPv4 address hostname used instead of legitimate domain", "critical"), ("keywords", "Keywords paytm-kyc-approval on untrusted host", "high")]
                ),
                (
                    "message",
                    "Hi Mom, I lost my phone and wallet. Please transfer 15000 urgently to this UPI id: emergency.help@upi",
                    78,
                    "High Risk",
                    "UPI payment fraud",
                    "Impersonation urgency fraud soliciting direct money transfer via UPI under emergency pretexts.",
                    ["Call your relative directly on their known phone number.", "Never send money to unverified UPI IDs.", "Verify caller identity before initiating payments."],
                    [("social_engineering", "Impersonating family member with urgent distress narrative", "high"), ("financial", "Direct unverified UPI address transfer request", "high")]
                ),
                (
                    "message",
                    "Meeting scheduled for tomorrow at 10 AM at the Bangalore main branch. Please bring your laptop.",
                    8,
                    "Low Risk",
                    "Legitimate communication",
                    "Normal business communication with no deceptive links, financial solicitations, urgency triggers, or credential harvesting indicators.",
                    ["Standard safe business communication.", "Verify calendar invites as per normal routine."],
                    []
                ),
            ]

            for stype, preview, score, level, cat, explanation, recs, evidence in sample_scans:
                s = Scan(user_id=uid, scan_type=stype, input_preview=preview, status="completed")
                db.session.add(s)
                db.session.flush()

                sr = ScanResult(
                    scan_id=s.id,
                    risk_score=score,
                    risk_level=level,
                    predicted_category=cat,
                    model_version="v1.0.0",
                    confidence=score / 100.0,
                    explanation=explanation,
                )
                sr.set_recommendations_list(recs)
                db.session.add(sr)
                db.session.flush()

                for etype, edesc, esev in evidence:
                    ev = ScanEvidence(
                        scan_result_id=sr.id,
                        evidence_type=etype,
                        evidence_description=edesc,
                        severity=esev,
                    )
                    db.session.add(ev)

                sh = ScanHistory(scan_id=s.id, user_id=uid, action_taken="scanned")
                db.session.add(sh)

            db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error during default seeding: {e}")


def _register_error_handlers(app):
    """Centralized HTTP and application error handlers."""

    @app.errorhandler(400)
    def bad_request(e):
        return render_template("errors/400.html", error=e), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html", error=e), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html", error=e), 404

    @app.errorhandler(413)
    def request_entity_too_large(e):
        return jsonify({"success": False, "error": "Uploaded file exceeds maximum permitted size (16MB)."}), 413

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("errors/500.html", error=e), 500
