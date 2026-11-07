# 🛡️ ScamShield AI
### Advanced AI-Powered Scam Detection and Fraud Prevention Web Application

[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Flask Version](https://img.shields.io/badge/Flask-3.1.3-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Tests Passing](https://img.shields.io/badge/Pytest-33%20Passed-brightgreen.svg)]()

**ScamShield AI** is an enterprise-grade cybersecurity web application built to analyze suspicious digital communications and documents commonly encountered across India. The platform analyzes SMS messages, WhatsApp chats, emails, URLs, screenshots, and PDF invoices to identify fraudulent patterns, assign a calibrated risk score (0–100), explain warning indicators, and deliver actionable safety recommendations.

---
## 👨‍💻 Author

**Jeevan K B**

Department of Computer Science and Engineering (CSE)  
City Engineering College, Bengaluru, Karnataka, India.

### Project

**ScamShield AI — AI-Powered Scam Detection and Fraud Prevention Platform**

Developed as an academic project to explore machine learning, cybersecurity, NLP and digital fraud detection.

### Connect

- GitHub: [jeevankb-cse](https://github.com/jeevankb-cse)
- Repository: [ScamShield-AI](https://github.com/jeevankb-cse/ScamShield-AI)


## 📑 Table of Contents

- [1. Key Features](#1-key-features)
- [2. Supported Scam Categories](#2-supported-scam-categories)
- [3. Architecture & Tech Stack](#3-architecture--tech-stack)
- [4. Project Folder Structure](#4-project-folder-structure)
- [5. Installation Guide (Windows 11)](#5-installation-guide-windows-11)
- [6. Database Setup (MySQL 8 & SQLite Fallback)](#6-database-setup-mysql-8--sqlite-fallback)
- [7. Tesseract OCR Setup](#7-tesseract-ocr-setup)
- [8. Model Training & Evaluation](#8-model-training--evaluation)
- [9. Running the Application](#9-running-the-application)
- [10. Running Test Suite](#10-running-test-suite)
- [11. API Endpoints](#11-api-endpoints)
- [12. Security & Privacy Safeguards](#12-security--privacy-safeguards)
- [13. Known Limitations](#13-known-limitations)
- [14. Emergency Helpline Contacts](#14-emergency-helpline-contacts)

---

## 1. Key Features

- **📱 SMS & WhatsApp Message Scanner:** Scans chat text using NLP preprocessing and Multinomial Naive Bayes/Logistic Regression classifiers. Identifies urgency coercion, UPI PIN requests, and embedded links.
- **✉️ Email Phishing Scanner:** Analyzes sender domains, flags lookalike typosquatting (`sbi-security.com`), detects free webmail authority impersonation (`@gmail.com` claiming to be Income Tax Department), and parses deceptive refund deadlines.
- **🌐 Lexical URL Scanner:** Evaluates 15 lexical and structural characteristics (length, dot count, raw IPv4 hostnames, excessive subdomains, suspicious TLDs like `.xyz`/`.top`). **Zero-execution and SSRF-protected** (untrusted URLs are never fetched or browsed).
- **📸 Screenshot & Image Scanner:** Uses OpenCV image preprocessing (adaptive thresholding, denoising) and Tesseract OCR to extract text from chat screenshots, forwarding content to the threat engine.
- **📄 PDF Invoice Validator:** Employs PyMuPDF (`fitz`) to extract invoice numbers, Indian GSTIN (15-character format validation), dates, and bank account details. Conducts line-item arithmetic consistency checks and flags unauthorized bank detail change notices. Supports optional comparison against a reference invoice.
- **🎯 Calibrated Risk Engine:** Produces a standardized 0–100 risk score with display bands:
  - `0–29`: **Low Risk** (Emerald Green)
  - `30–59`: **Medium Risk** (Amber Orange)
  - `60–79`: **High Risk** (Orange Red)
  - `80–100`: **Very High Risk** (Crimson Red)
- **📊 Interactive Cybersecurity Dashboard:** Real-time analytics built with Chart.js including category distribution, input type breakdowns, 7-day scanning volume, and recent scan logs.
- **🔐 Enterprise Authentication & RBAC:** Secure password hashing (Scrypt/Werkzeug), role-based access control (`user` vs `admin`), searchable user scan history, profile password management, and security audit logging.
- **👑 Admin Management Console:** Inspect platform user status, view audit logs, and review held-out test evaluation reports (accuracy, precision, recall, F1, confusion matrix) for all models.

---

## 2. Supported Scam Categories

ScamShield AI identifies and documents 14 specific cyber fraud vectors active in India:

1. **Phishing attacks**
2. **Fake KYC updates** (PAN/Aadhaar/SIM deactivation threats)
3. **UPI payment fraud** (PIN requests to receive cashback)
4. **Fake job offers** (YouTube liking, Telegram part-time task scams)
5. **Loan scams** (Predatory instant APK loans, zero CIBIL check traps)
6. **Lottery and prize scams** (Unearned KBC/lottery winnings)
7. **Refund scams** (Fake income tax, electricity, or utility refund portals)
8. **Courier and delivery scams** (India Post / FedEx parcel seized notices)
9. **Bank impersonation** (Spoofed SBI, HDFC, ICICI alerts)
10. **Government impersonation** (PIB, Income Tax, Cyber Cell, Police)
11. **Digital arrest threats** (Extortion via Skype/WhatsApp video calls claiming CBI/Customs warrants)
12. **OTP and PIN harvesting** (Direct credential solicitations)
13. **Malicious URLs** (Raw IP addresses, typosquatted hostnames, abused TLDs)
14. **Fake invoice & supplier fraud** (Altered bank details and mismatched tax math)

---

## 3. Architecture & Tech Stack

```
   ┌─────────────────────────────────────────────────────────────┐
   │                     Client Browser                          │
   │   (HTML5, CSS3 Navy SaaS Theme, Vanilla JS, Chart.js)       │
   └──────────────────────────────┬──────────────────────────────┘
                                  │ HTTPS / REST API
   ┌──────────────────────────────▼──────────────────────────────┐
   │                   Flask 3.1 Backend                         │
   │  ┌───────────────┐ ┌───────────────┐ ┌───────────────────┐  │
   │  │ Auth (Login)  │ │ Scan Routes   │ │ Admin & Dashboard │  │
   │  └───────┬───────┘ └───────┬───────┘ └─────────┬─────────┘  │
   │          │                 │                   │            │
   │  ┌───────▼─────────────────▼───────────────────▼─────────┐  │
   │  │                     Services Layer                    │  │
   │  │  • Text Analyzer       • URL Analyzer (SSRF-Safe)     │  │
   │  │  • Email Analyzer      • Image OCR (OpenCV+Tesseract) │  │
   │  │  • PDF PyMuPDF Parser  • Invoice Rule Engine          │  │
   │  │  • Risk Engine         • Explanation Engine           │  │
   │  └─────────────────────────┬─────────────────────────────┘  │
   │                            │                                │
   │  ┌─────────────────────────▼─────────────────────────────┐  │
   │  │                   ML Inference Layer                  │  │
   │  │  • Text Classifier (TF-IDF + Multinomial Naive Bayes) │  │
   │  │  • URL Phishing Model (Random Forest Classifier)      │  │
   │  │  • Email Classifier (TF-IDF + Logistic Regression)    │  │
   │  └─────────────────────────┬─────────────────────────────┘  │
   └────────────────────────────┼────────────────────────────────┘
                                │ SQLAlchemy ORM
   ┌────────────────────────────▼────────────────────────────────┐
   │          Database Layer: MySQL 8 (or SQLite Fallback)       │
   │   (users, scans, scan_results, scan_evidence, audit_logs)   │
   └─────────────────────────────────────────────────────────────┘
```

- **Backend:** Python 3.10 / 3.13, Flask 3.1.3, Flask-Login, Flask-SQLAlchemy
- **Frontend:** HTML5, Modern CSS3 Navy Cybersecurity Theme, Vanilla JS, Chart.js 4.4
- **Database:** MySQL 8.0+ (with seamless SQLite fallback for local development)
- **Machine Learning:** Scikit-Learn, Pandas, NumPy, Joblib
- **NLP & Regex:** NLTK, Regular Expressions
- **Document & Image Processing:** PyMuPDF (`fitz`), Pillow, OpenCV (`cv2`), pytesseract
- **Testing:** Pytest (33 unit and integration tests)

---

## 4. Project Folder Structure

```
ScamShield-AI/
├── app.py                     # Application entry point
├── config.py                  # Environment & database configuration
├── requirements.txt           # Python dependency specifications
├── .env.example               # Environment template
├── .env                       # Active environment variables
├── .gitignore                 # Git ignore rules
├── README.md                  # Comprehensive documentation
│
├── app/
│   ├── __init__.py            # Flask factory (create_app), security headers, DB setup
│   ├── extensions.py          # SQLAlchemy and LoginManager instances
│   ├── routes/
│   │   ├── auth_routes.py     # Login, Register, Logout
│   │   ├── dashboard_routes.py# Dashboard, Chart.js stats, About page
│   │   ├── scan_routes.py     # Multi-scanner & REST APIs
│   │   ├── history_routes.py  # User scan archive & Profile
│   │   └── admin_routes.py    # Admin console & Model reports
│   ├── services/
│   │   ├── text_analyzer.py   # SMS/WhatsApp scanner
│   │   ├── email_analyzer.py  # Email scanner
│   │   ├── url_analyzer.py    # Lexical URL analyzer (SSRF-protected)
│   │   ├── image_analyzer.py  # OpenCV + Tesseract OCR scanner
│   │   ├── pdf_analyzer.py    # PyMuPDF text & metadata extraction
│   │   ├── invoice_analyzer.py# Hybrid explainable invoice validator
│   │   ├── risk_engine.py     # Composite risk scoring (0-100)
│   │   └── explanation_engine.py # Human explanations & safety actions
│   ├── ml/
│   │   ├── model_loader.py    # Singleton registry for cached models
│   │   ├── text_predictor.py  # Text ML inference
│   │   └── url_predictor.py   # URL feature extraction & ML inference
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py            # User model with role checking
│   │   ├── scan.py            # Scan, ScanHistory, AuditLog models
│   │   └── scan_result.py     # ScanResult and ScanEvidence models
│   ├── utils/
│   │   ├── text_preprocessing.py # NLP cleaning, regex entity extractors
│   │   ├── validators.py      # Input validation & SSRF protection
│   │   └── file_security.py   # Magic byte validation, safe deletion
│   ├── templates/             # 12 HTML5 Jinja templates
│   │   ├── base.html
│   │   ├── index.html
│   │   ├── login.html
│   │   ├── register.html
│   │   ├── dashboard.html
│   │   ├── scan.html
│   │   ├── scan_result.html
│   │   ├── history.html
│   │   ├── profile.html
│   │   ├── admin.html
│   │   ├── about.html
│   │   └── errors/            # 400, 403, 404, 500 error pages
│   └── static/
│       ├── css/style.css      # Dark Navy SaaS theme styles
│       ├── js/
│       │   ├── main.js        # Global clipboard & alert helpers
│       │   ├── scanner.js     # Tab switcher & AJAX file uploaders
│       │   └── dashboard.js   # Chart.js graphs
│       └── images/
│
├── ml/
│   ├── datasets/raw/          # Raw datasets (SMS, URLs, Emails)
│   ├── training/
│   │   ├── train_text_model.py  # MultinomialNB vs LogisticRegression
│   │   ├── train_url_model.py   # Random Forest vs LogisticRegression
│   │   └── train_email_model.py # TF-IDF email classifier
│   ├── artifacts/             # Persisted .joblib models & vectorizers
│   └── reports/               # Verified evaluation JSON reports
│
├── database/
│   ├── schema.sql             # MySQL 8 table definitions
│   └── seed_data.sql          # Sample data & initial accounts
│
├── uploads/                   # Temporary directory (auto-purged)
├── logs/                      # Rotating application logs
└── tests/                     # 33 Pytest test suites
    ├── conftest.py
    ├── test_auth.py
    ├── test_models.py
    ├── test_text_scanner.py
    ├── test_email_scanner.py
    ├── test_url_scanner.py
    ├── test_image_ocr.py
    ├── test_pdf_invoice.py
    ├── test_risk_engine.py
    ├── test_api.py
    └── test_security.py
```

---

## 5. Installation Guide (Windows 11)

### Prerequisites
- Python 3.10+ (or 3.13)
- MySQL Server 8.0+ (Optional; fallback SQLite is built-in)
- Git (Optional)
- Tesseract OCR (Optional; image scanner gracefully notifies if absent)

### Step 1: Open PowerShell and Navigate to the Project Directory
```powershell
cd C:\Users\jeeva\.gemini\antigravity\scratch\ScamShield-AI
```

### Step 2: Create and Activate a Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Required Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Download NLTK Tokenizer Data
```powershell
python -c "import nltk; nltk.download('punkt'); nltk.download('punkt_tab'); nltk.download('stopwords')"
```

---

## 6. Database Setup (MySQL 8 & SQLite Fallback)

### Option A: MySQL 8 Database Setup
1. Start your local MySQL 8 server.
2. Log into the MySQL command line client:
```powershell
mysql -u root -p
```
3. Run the schema creation script:
```sql
SOURCE database/schema.sql;
SOURCE database/seed_data.sql;
EXIT;
```
4. Verify or update your `.env` configuration:
```env
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=scamshield_db
```

### Option B: Automatic SQLite Fallback
If MySQL is not installed or running, ScamShield AI **automatically activates a fallback SQLite database** (`database/scamshield.db`) upon startup and auto-seeds the default admin and demo user. Zero extra configuration required.

### Pre-Configured Demo Credentials:
- **Admin Account:** `admin` / `Admin@123`
- **Standard Account:** `user` / `User@123`

---

## 7. Tesseract OCR Setup

1. Download the official Windows Tesseract OCR installer from [UB-Mannheim](https://github.com/UB-Mannheim/tesseract/wiki).
2. Install to the default directory: `C:\Program Files\Tesseract-OCR\tesseract.exe`.
3. In your `.env` file, ensure:
```env
TESSERACT_CMD=C:\Program Files\Tesseract-OCR\tesseract.exe
```
*Note: If Tesseract is not installed on the system, ScamShield AI will safely handle image uploads with a clear notification rather than crashing.*

---

## 8. Model Training & Evaluation

The machine learning models can be trained or re-trained using the provided training scripts. Held-out test evaluation reports will be saved automatically to `ml/reports/`.

```powershell
# Train Text Classifier (Multinomial Naive Bayes)
python ml\training\train_text_model.py

# Train URL Classifier (Random Forest)
python ml\training\train_url_model.py

# Train Email Classifier (Logistic Regression)
python ml\training\train_email_model.py
```

### Real Evaluation Results (Held-Out Test Sets):
- **Text Scam Classifier:** Accuracy: `88.9%`, F1-Score: `0.9091`, Precision: `83.3%`, Recall: `100%`
- **URL Phishing Classifier:** Accuracy: `100%`, F1-Score: `1.0000`, Precision: `100%`, Recall: `100%`
- **Email Phishing Classifier:** Accuracy: `60.0%`, F1-Score: `0.6667`, Precision: `50.0%`, Recall: `100%`

*Evaluation metrics are verifiable in `ml/reports/` and rendered inside the Admin Portal.*

---

## 9. Running the Application

Start the Flask development server:

```powershell
python app.py
```

You should see:
```
============================================================
   SCAMSHIELD AI - Advanced Threat Detection Web Application
   Server listening at: http://127.0.0.1:5000
============================================================
```

Open your browser and navigate to: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 10. Running Test Suite

ScamShield AI includes a 33-test suite covering authentication, scanners, file security, PDF validation, OCR handling, and API endpoints.

```powershell
pytest -v
```

### Output:
```
tests/test_api.py::test_api_scan_text PASSED                             [  3%]
tests/test_api.py::test_api_scan_email PASSED                            [  6%]
tests/test_api.py::test_api_scan_url PASSED                              [  9%]
tests/test_api.py::test_api_get_scan_details PASSED                      [ 12%]
tests/test_api.py::test_api_dashboard_stats PASSED                       [ 15%]
tests/test_auth.py::test_user_registration PASSED                        [ 18%]
tests/test_auth.py::test_registration_password_mismatch PASSED           [ 21%]
tests/test_auth.py::test_login_success_and_logout PASSED                 [ 24%]
tests/test_auth.py::test_login_invalid_password PASSED                   [ 27%]
tests/test_email_scanner.py::test_spoofed_bank_email PASSED              [ 30%]
tests/test_email_scanner.py::test_free_webmail_authority_spoof PASSED    [ 33%]
tests/test_email_scanner.py::test_legitimate_newsletter_email PASSED     [ 36%]
tests/test_image_ocr.py::test_image_preprocessing PASSED                 [ 39%]
tests/test_image_ocr.py::test_image_analyzer_execution PASSED            [ 42%]
tests/test_models.py::test_user_model PASSED                             [ 45%]
tests/test_models.py::test_scan_and_result_relationship PASSED           [ 48%]
tests/test_pdf_invoice.py::test_invoice_with_bank_change_and_arithmetic_mismatch PASSED [ 51%]
tests/test_pdf_invoice.py::test_invoice_with_comparison_mismatch PASSED  [ 54%]
tests/test_risk_engine.py::test_risk_level_banding PASSED                [ 57%]
tests/test_risk_engine.py::test_composite_risk_critical_override PASSED  [ 60%]
tests/test_risk_engine.py::test_recommendations_consistency PASSED       [ 63%]
tests/test_security.py::test_reject_executable_upload PASSED             [ 66%]
tests/test_security.py::test_reject_spoofed_file_extension PASSED        [ 69%]
tests/test_security.py::test_ssrf_private_network_protection PASSED      [ 72%]
tests/test_security.py::test_admin_route_authorization_boundaries PASSED [ 75%]
tests/test_text_scanner.py::test_scan_fake_kyc_message PASSED            [ 78%]
tests/test_text_scanner.py::test_scan_upi_pin_fraud PASSED               [ 81%]
tests/test_text_scanner.py::test_scan_digital_arrest_threat PASSED       [ 84%]
tests/test_text_scanner.py::test_scan_legitimate_message PASSED          [ 87%]
tests/test_url_scanner.py::test_raw_ip_url_detection PASSED              [ 90%]
tests/test_url_scanner.py::test_suspicious_tld_and_phish_keywords PASSED [ 93%]
tests/test_url_scanner.py::test_ssrf_protection_blocked PASSED           [ 96%]
tests/test_url_scanner.py::test_legitimate_url PASSED                    [100%]

============================= 33 passed in 16.39s =============================
```

---

## 11. API Endpoints

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/` | Landing page | No |
| `GET` | `/dashboard` | User dashboard & telemetry | Yes |
| `GET` | `/scan` | Multi-input scanner UI | No |
| `GET` | `/scan/<id>` | Detailed scan report | Owner / Admin |
| `GET` | `/history` | Historical scans archive | Yes |
| `GET` | `/profile` | Profile & password update | Yes |
| `GET` | `/admin` | Admin dashboard & model metrics | Admin only |
| `POST` | `/register` | Register new user account | No |
| `POST` | `/login` | Authenticate user session | No |
| `POST` | `/logout` | Terminate session | Yes |
| `POST` | `/api/scan/text` | Scan SMS/WhatsApp text | No |
| `POST` | `/api/scan/email` | Scan email headers & body | No |
| `POST` | `/api/scan/url` | Lexical URL scan (SSRF safe) | No |
| `POST` | `/api/scan/image` | Scan screenshot via OCR | No |
| `POST` | `/api/scan/pdf` | Validate PDF invoice & math | No |
| `GET` | `/api/scans/<id>` | Retrieve scan report JSON | Owner / Admin |
| `GET` | `/api/dashboard/stats` | Chart.js aggregated stats | Yes |

---

## 12. Security & Privacy Safeguards

- **SSRF Prevention:** Submitted URLs are inspected through lexical parsing. They are never fetched via HTTP requests by the server. Loopback (`127.0.0.1`), private RFC1918 subnets, and cloud metadata endpoints (`169.254.169.254`) are systematically blocked.
- **Magic Byte File Inspection:** File validation verifies binary magic headers (JPEG `FF D8 FF`, PNG `89 50 4E 47`, WEBP `RIFF...WEBP`, PDF `%PDF-`), preventing spoofed extensions.
- **Immediate File Purging:** All uploaded screenshot images and PDF invoices are deleted from the `uploads/` folder immediately after feature extraction.
- **Credential Redaction:** Potential OTPs, PINs, and sensitive credentials are masked prior to database persistence and preview display.
- **Security Headers:** Every HTTP response includes `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, and `Referrer-Policy: strict-origin-when-cross-origin`.

---

## 13. Known Limitations

- **Probabilistic Risk Assessments:** Model predictions and heuristic indicators reflect risk probabilities and do not represent absolute legal proof of fraud.
- **OCR Quality:** Highly compressed, low-resolution, or heavily skewed images may degrade OCR text recognition accuracy.
- **Novel Evasion Tactics:** Cybercriminals continually evolve text obfuscation techniques (e.g. zero-width characters, homoglyphs). While regex preprocessing normalizes many variants, users should always exercise standard caution.

---

## 14. Emergency Helpline Contacts

If you suspect you have fallen victim to financial fraud or shared sensitive credentials:

- 📞 **National Cybercrime Helpline:** Call **1930** (Toll-Free, 24x7)
- 🌐 **National Cybercrime Reporting Portal:** [https://cybercrime.gov.in](https://cybercrime.gov.in)
- 🛡️ **CERT-In Incident Response:** Email `incident@cert-in.org.in`
- 🏦 **Bank Emergency:** Immediately call your bank's toll-free emergency number to freeze your debit cards, net banking access, and UPI services.

---
*Built with ❤️ for Indian Cyber Defense by ScamShield AI.*
