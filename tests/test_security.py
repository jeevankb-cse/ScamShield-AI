import io
from app.utils.file_security import validate_upload, validate_file_content
from app.utils.validators import is_ssrf_safe_hostname


def test_reject_executable_upload(client):
    """Ensure executable files cannot be uploaded through scanners."""
    fake_exe = (io.BytesIO(b"MZ\x90\x00\x03\x00\x00\x00"), "malware.exe")
    resp = client.post("/api/scan/image", data={"file": fake_exe})
    assert resp.status_code == 400
    assert "Unsupported file type" in resp.get_json()["error"]


def test_reject_spoofed_file_extension(client):
    """File claims to be PNG but has text/binary garbage."""
    fake_png = (io.BytesIO(b"Hello world, not a real PNG image"), "fake.png")
    resp = client.post("/api/scan/image", data={"file": fake_png})
    assert resp.status_code == 400
    assert "does not match reported .png format" in resp.get_json()["error"]


def test_ssrf_private_network_protection():
    assert is_ssrf_safe_hostname("10.0.0.1") is False
    assert is_ssrf_safe_hostname("172.16.0.1") is False
    assert is_ssrf_safe_hostname("192.168.0.1") is False
    assert is_ssrf_safe_hostname("169.254.169.254") is False
    assert is_ssrf_safe_hostname("metadata.google.internal") is False


def test_admin_route_authorization_boundaries(app):
    """Verify unauthorized users are blocked from administrative console."""
    # 1. Unauthenticated -> 302 redirect to login
    anon_client = app.test_client()
    anon_resp = anon_client.get("/admin")
    assert anon_resp.status_code == 302

    # 2. Standard User -> 403 Forbidden
    user_client = app.test_client()
    login_user_res = user_client.post("/login", data={"identifier": "test_user", "password": "UserPass@123"}, follow_redirects=True)
    assert login_user_res.status_code == 200
    user_resp = user_client.get("/admin")
    assert user_resp.status_code == 403
    user_client.get("/logout")

    # 3. Admin User -> 200 OK
    admin_client = app.test_client()
    login_adm_res = admin_client.post("/login", data={"identifier": "test_admin", "password": "AdminPass@123"}, follow_redirects=True)
    assert login_adm_res.status_code == 200
    adm_resp = admin_client.get("/admin")
    assert adm_resp.status_code == 200
    assert b"Platform Administration" in adm_resp.data
