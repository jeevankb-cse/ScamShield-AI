import io
from app.models.scan import Scan


def test_api_scan_text(client):
    resp = client.post("/api/scan/text", json={
        "text": "Your SBI account is suspended due to missing PAN. Click http://sbi-pan.in"
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "scan_id" in data
    assert data["risk_score"] >= 60


def test_api_scan_email(client):
    resp = client.post("/api/scan/email", json={
        "sender": "alerts@sbi-security.org",
        "subject": "Action Required: Account Verification",
        "body": "Please verify your details at http://sbi-verify.org"
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "scan_id" in data


def test_api_scan_url(client):
    resp = client.post("/api/scan/url", json={
        "url": "http://192.168.1.1/paytm-kyc-verify"
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["hostname"] == "192.168.1.1"


def test_api_get_scan_details(auth_client, app):
    # Submit scan through API
    scan_resp = auth_client.post("/api/scan/text", json={
        "text": "Meeting scheduled tomorrow at office"
    })
    scan_id = scan_resp.get_json()["scan_id"]

    # Fetch scan via API
    get_resp = auth_client.get(f"/api/scans/{scan_id}")
    assert get_resp.status_code == 200
    res_data = get_resp.get_json()
    assert res_data["success"] is True
    assert res_data["scan"]["id"] == scan_id


def test_api_dashboard_stats(auth_client):
    resp = auth_client.get("/api/dashboard/stats")
    assert resp.status_code == 200
    stats = resp.get_json()
    assert "categories" in stats
    assert "scan_types" in stats
    assert "weekly_trend" in stats
