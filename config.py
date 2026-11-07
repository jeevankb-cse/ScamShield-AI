import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent

# Load environment variables
load_dotenv(BASE_DIR / ".env")


class Config:
    """Base application configuration."""

    SECRET_KEY = os.environ.get("SECRET_KEY", "scamshield-default-dev-secret-key-2026")
    FLASK_ENV = os.environ.get("FLASK_ENV", "development")
    DEBUG = os.environ.get("DEBUG", "True").lower() in ("true", "1", "yes")

    # Uploads
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024))  # 16 MB
    UPLOAD_FOLDER = BASE_DIR / os.environ.get("UPLOAD_FOLDER", "uploads")
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "pdf"}

    # Database Configuration
    # Uses MySQL by default, but provides seamless fallback to SQLite for development
    DB_USER = os.environ.get("DB_USER", "root")
    DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
    DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
    DB_PORT = os.environ.get("DB_PORT", "3306")
    DB_NAME = os.environ.get("DB_NAME", "scamshield_db")

    custom_db_url = os.environ.get("DATABASE_URL")
    if custom_db_url:
        SQLALCHEMY_DATABASE_URI = custom_db_url
    else:
        # Default MySQL URI
        SQLALCHEMY_DATABASE_URI = (
            f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
        )

    # SQLite fallback URI if MySQL connection cannot be established
    FALLBACK_DATABASE_URI = f"sqlite:///{BASE_DIR / 'database' / 'scamshield.db'}"

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 280,
        "pool_pre_ping": True,
    }

    # Tesseract OCR executable path
    TESSERACT_CMD = os.environ.get("TESSERACT_CMD", r"C:\Program Files\Tesseract-OCR\tesseract.exe")

    # ML Artifacts path
    ML_ARTIFACTS_DIR = BASE_DIR / "ml" / "artifacts"
    ML_REPORTS_DIR = BASE_DIR / "ml" / "reports"
    LOGS_DIR = BASE_DIR / "logs"


class TestingConfig(Config):
    """Testing configuration."""

    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{BASE_DIR / 'database' / 'test_scamshield.db'}"
    WTF_CSRF_ENABLED = False
