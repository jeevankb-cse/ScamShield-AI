import json
import os
import sys
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report

from app.utils.text_preprocessing import clean_text_for_nlp


def train_email_classifier():
    print("=" * 60)
    print("SCAMSHIELD AI: TRAINING EMAIL PHISHING CLASSIFIER")
    print("=" * 60)

    dataset_path = ROOT_DIR / "ml" / "datasets" / "raw" / "emails_dataset.csv"
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")

    df = pd.read_csv(dataset_path, comment="#")
    print(f"Loaded {len(df)} email samples.")
    print(f"Class distribution:\n{df['label'].value_counts()}")

    # Combine sender, subject, and body for comprehensive email feature representation
    def prepare_email_text(row):
        sender = str(row["sender"]) if pd.notna(row["sender"]) else ""
        subject = str(row["subject"]) if pd.notna(row["subject"]) else ""
        body = str(row["body"]) if pd.notna(row["body"]) else ""
        return f"{sender} {subject} {subject} {body}"

    df["full_text"] = df.apply(prepare_email_text, axis=1)
    df["cleaned_text"] = df["full_text"].apply(clean_text_for_nlp)

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        df["cleaned_text"], df["label"], test_size=0.25, random_state=42, stratify=df["label"]
    )
    print(f"Training set: {len(X_train)} samples | Test set: {len(X_test)} samples")

    # TF-IDF vectorization
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=3000, sublinear_tf=True)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # Model 1: Naive Bayes
    mnb = MultinomialNB(alpha=0.5)
    mnb.fit(X_train_vec, y_train)
    y_pred_mnb = mnb.predict(X_test_vec)
    f1_mnb = f1_score(y_test, y_pred_mnb, zero_division=0)

    # Model 2: Logistic Regression
    lr = LogisticRegression(max_iter=500, random_state=42)
    lr.fit(X_train_vec, y_train)
    y_pred_lr = lr.predict(X_test_vec)
    f1_lr = f1_score(y_test, y_pred_lr, zero_division=0)

    print(f"\nModel Comparison on Held-Out Test Set:")
    print(f" - Multinomial Naive Bayes F1: {f1_mnb:.4f}")
    print(f" - Logistic Regression F1:    {f1_lr:.4f}")

    if f1_lr >= f1_mnb:
        best_model = lr
        best_name = "Logistic Regression"
        y_pred = y_pred_lr
    else:
        best_model = mnb
        best_name = "Multinomial Naive Bayes"
        y_pred = y_pred_mnb

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

    model_file = artifacts_dir / "email_classifier.joblib"
    vec_file = artifacts_dir / "email_vectorizer.joblib"
    joblib.dump(best_model, model_file)
    joblib.dump(vectorizer, vec_file)

    report_data = {
        "model_type": best_name,
        "dataset": "Email Phishing & Corporate Communications Dataset v1.0.0",
        "train_samples": len(X_train),
        "test_samples": len(X_test),
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

    with open(reports_dir / "email_model_report.json", "w") as f:
        json.dump(report_data, f, indent=2)

    print(f"Model saved to: {model_file}")
    print(f"Vectorizer saved to: {vec_file}")
    print(f"Evaluation report saved to: {reports_dir / 'email_model_report.json'}")
    return report_data


if __name__ == "__main__":
    train_email_classifier()
