import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "True").lower() in ("true", "1", "yes")
    print("=" * 60)
    print("   SCAMSHIELD AI - Advanced Threat Detection Web Application")
    print(f"   Server listening at: http://127.0.0.1:{port}")
    print("=" * 60)
    app.run(host="0.0.0.0", port=port, debug=debug)
