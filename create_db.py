import app
from app import create_app, db
flask_app = create_app()               # reads .env (SQLite forced)
with flask_app.app_context():
    db.create_all()
    print("✅ DB tables created (SQLite)")
