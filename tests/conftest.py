import pytest
from pathlib import Path
import os
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.extensions import db
from app.models.user import User
from config import TestingConfig


@pytest.fixture
def app():
    """Create and configure a clean Flask application instance for testing."""
    test_app = create_app(TestingConfig)

    with test_app.app_context():
        db.create_all()
        from app import _seed_initial_defaults
        _seed_initial_defaults(test_app)

        # Seed test admin and user if not existing
        if not User.query.filter_by(username="test_admin").first():
            admin = User(username="test_admin", email="admin@test.local", role="admin")
            admin.set_password("AdminPass@123")
            db.session.add(admin)

        if not User.query.filter_by(username="test_user").first():
            user = User(username="test_user", email="user@test.local", role="user")
            user.set_password("UserPass@123")
            db.session.add(user)

        db.session.commit()

        yield test_app

        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test HTTP client."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Test CLI runner."""
    return app.test_cli_runner()


@pytest.fixture
def auth_client(app):
    """Authenticated user test client."""
    c = app.test_client()
    c.post("/login", data={"identifier": "test_user", "password": "UserPass@123"})
    return c


@pytest.fixture
def admin_client(app):
    """Authenticated admin test client."""
    c = app.test_client()
    c.post("/login", data={"identifier": "test_admin", "password": "AdminPass@123"})
    return c
