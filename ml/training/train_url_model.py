import ipaddress
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report

SUSPICIOUS_TLDS = {".xyz", ".top", ".buzz", ".club", ".tk", ".ml", ".ga", ".cc", ".online", ".site", ".work", ".info"}
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "bank", "secure", "kyc", "reward", "claim",
    "refund", "account", "password", "otp", "blocked", "bonus", "free", "cashback", "wallet"
]

FEATURE_NAMES = [
    "url_length",
    "host_length",
    "path_length",
    "count_dots",
    "count_hyphens",
    "count_at",
    "count_question",
    "count_equal",
    "count_slashes",
    "count_digits",
    "has_ip_address",
    "num_subdomains",
    "has_suspicious_tld",
    "has_phish_keyword",
    "is_https"
]


def extract_url_features(url_str: str) -> list:
    """Extract 15 numerical and structural lexical features from URL."""
    if not url_str.startswith("http://") and not url_str.startswith("https://"):
        url_str = "http://" + url_str

    try:
        parsed = urlparse(url_str)
    except Exception:
        parsed = urlparse("http://invalid.invalid")

    hostname = parsed.hostname or ""
    path = parsed.path or ""

    # Feature 1: URL Length
    url_len = len(url_str)
    # Feature 2: Host Length
    host_len = len(hostname)
    # Feature 3: Path Length
    path_len = len(path)
    # Feature 4: Dot count
    dots = url_str.count(".")
    # Feature 5: Hyphen count
    hyphens = url_str.count("-")
    # Feature 6: At symbol count
    at_count = url_str.count("@")
    # Feature 7: Question mark count
    question_count = url_str.count("?")
    # Feature 8: Equal sign count
    equal_count = url_str.count("=")
    # Feature 9: Slash count
    slash_count = url_str.count("/")
    # Feature 10: Digits count
    digits_count = sum(c.isdigit() for c in url_str)

    # Feature 11: IP address hostname
    has_ip = 0
    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    # Feature 12: Subdomain count
    subdomains = max(0, len(hostname.split(".")) - 2) if not has_ip else 0

    # Feature 13: Suspicious TLD
    has_suspicious_tld = 1 if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0

    # Feature 14: Phishing keywords in URL
    url_lower = url_str.lower()
    has_keyword = 1 if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS) else 0

    # Feature 15: Is HTTPS
    is_https = 1 if parsed.scheme.lower() == "https" else 0

    return [
        url_len, host_len, path_len, dots, hyphens, at_count,
        question_count, equal_count, slash_count, digits_count,
        has_ip, subdomains, has_suspicious_tld, has_keyword, is_https
    ]


def train_url_classifier():
    print("=" * 60)
    print("SCAMSHIELD AI: TRAINING URL PHISHING CLASSIFIER")
    print("=" * 60)

    dataset_path = ROOT_DIR / "ml" / "datasets" / "raw" / "urls_dataset.csv"
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")

    df = pd.read_csv(dataset_path, comment="#")
    print(f"Loaded {len(df)} URL samples.")
    print(f"Class distribution:\n{df['label'].value_counts()}")

    # Extract feature matrix
    print("Extracting lexical and structural URL features...")
    feature_rows = [extract_url_features(u) for u in df["url"]]
    X = np.array(feature_rows)
    y = df["label"].values

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    print(f"Training set: {len(X_train)} samples | Test set: {len(X_test)} samples")

    # Baseline 1: Logistic Regression
    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr.fit(X_train, y_train)
    y_pred_lr = lr.predict(X_test)
    f1_lr = f1_score(y_test, y_pred_lr, zero_division=0)

    # Baseline 2: Random Forest Classifier
    rf = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42)
    rf.fit(X_train, y_train)
    y_pred_rf = rf.predict(X_test)
    f1_rf = f1_score(y_test, y_pred_rf, zero_division=0)

    print(f"\nModel Comparison on Held-Out Test Set:")
    print(f" - Logistic Regression F1:    {f1_lr:.4f}")
    print(f" - Random Forest F1:          {f1_rf:.4f}")

    if f1_rf >= f1_lr:
        best_model = rf
        best_name = "Random Forest"
        y_pred = y_pred_rf
    else:
        best_model = lr
        best_name = "Logistic Regression"
        y_pred = y_pred_lr

    print(f"\nSelected Model: {best_name}")

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    report = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"], output_dict=True, zero_division=0)

    print("\nEvaluation Results on Test Set:")
    print(f" - Accuracy:  {acc:.4f}")
    print(f" - Precision: {prec:.4f}")
    print(f" - Recall:    {rec:.4f}")
    print(f" - F1-Score:  {f1:.4f}")
    print(f" - Confusion Matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}")

    artifacts_dir = ROOT_DIR / "ml" / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = ROOT_DIR / "ml" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    model_file = artifacts_dir / "url_classifier.joblib"
    meta_file = artifacts_dir / "url_feature_names.joblib"
    joblib.dump(best_model, model_file)
    joblib.dump(FEATURE_NAMES, meta_file)

    report_data = {
        "model_type": best_name,
        "dataset": "Legitimate & Phishing URLs Curated Benchmark v1.0.0",
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "feature_count": len(FEATURE_NAMES),
        "features": FEATURE_NAMES,
        "metrics": {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "confusion_matrix": {
                "true_negatives": int(tn),
                "false_positives": int(fp),
                "false_negatives": int(fn),
                "true_positives": int(tp)
            },
            "classification_report": report
        },
        "model_version": "v1.0.0"
    }

    with open(reports_dir / "url_model_report.json", "w") as f:
        json.dump(report_data, f, indent=2)

    print(f"Model saved to: {model_file}")
    print(f"Feature metadata saved to: {meta_file}")
    print(f"Evaluation report saved to: {reports_dir / 'url_model_report.json'}")
    return report_data


if __name__ == "__main__":
    train_url_classifier()
