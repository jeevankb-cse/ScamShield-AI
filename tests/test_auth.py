import pytest
from app.models.user import User


def test_user_registration(client, app):
    """Test standard user registration flow."""
    resp = client.post("/register", data={
        "username": "newdefender",
        "email": "defender@shield.ai",
        "password": "StrongPassword@123",
        "confirm_password": "StrongPassword@123"
    }, follow_redirects=True)

    assert resp.status_code == 200
    with app.app_context():
        u = User.query.filter_by(username="newdefender").first()
        assert u is not None
        assert u.email == "defender@shield.ai"
        assert u.check_password("StrongPassword@123")
        assert not u.check_password("WrongPassword")


def test_registration_password_mismatch(client):
    """Test registration with mismatched passwords."""
    resp = client.post("/register", data={
        "username": "mismatchuser",
        "email": "mismatch@shield.ai",
        "password": "PasswordA@123",
        "confirm_password": "PasswordB@123"
    }, follow_redirects=True)

    assert resp.status_code == 200
    assert b"Passwords do not match" in resp.data


def test_login_success_and_logout(client):
    """Test successful login and subsequent logout."""
    login_resp = client.post("/login", data={
        "identifier": "test_user",
        "password": "UserPass@123"
    }, follow_redirects=True)
    assert login_resp.status_code == 200
    assert b"Welcome back, test_user" in login_resp.data

    logout_resp = client.get("/logout", follow_redirects=True)
    assert logout_resp.status_code == 200
    assert b"You have been securely logged out" in logout_resp.data


def test_login_invalid_password(client):
    """Test login rejection on incorrect password."""
    resp = client.post("/login", data={
        "identifier": "test_user",
        "password": "IncorrectPassword@999"
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Invalid username/email or password" in resp.data
