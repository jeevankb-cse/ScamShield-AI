from app.extensions import db
from app.models.user import User
from app.models.scan import Scan, ScanHistory, AuditLog
from app.models.scan_result import ScanResult, ScanEvidence


def test_user_model(app):
    with app.app_context():
        u = User(username="analyst1", email="analyst@scamshield.ai", role="admin")
        u.set_password("SecurePass@123")
        db.session.add(u)
        db.session.commit()

        assert u.id is not None
        assert u.is_admin() is True
        assert u.check_password("SecurePass@123") is True
        assert u.to_dict()["username"] == "analyst1"


def test_scan_and_result_relationship(app):
    with app.app_context():
        scan = Scan(scan_type="message", input_preview="Dear customer, account locked", status="completed")
        db.session.add(scan)
        db.session.flush()

        result = ScanResult(
            scan_id=scan.id,
            risk_score=85,
            risk_level="Very High Risk",
            predicted_category="Fake KYC updates",
            explanation="Account phishing indicators found",
        )
        result.set_recommendations_list(["Do not click links", "Call official bank number"])
        db.session.add(result)
        db.session.flush()

        evidence = ScanEvidence(
            scan_result_id=result.id,
            evidence_type="urgency",
            evidence_description="Urgent deadline detected",
            severity="high"
        )
        db.session.add(evidence)
        db.session.commit()

        # Check cascading and relationships
        loaded = db.session.get(Scan, scan.id)
        assert loaded.result is not None
        assert loaded.result.risk_score == 85
        assert len(loaded.result.evidence_items) == 1
        assert "Do not click links" in loaded.result.get_recommendations_list()
