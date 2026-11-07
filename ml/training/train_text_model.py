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


def train_text_classifier():
    print("=" * 60)
    print("SCAMSHIELD AI: TRAINING TEXT SCAM CLASSIFIER")
    print("=" * 60)

    dataset_path = ROOT_DIR / "ml" / "datasets" / "raw" / "sms_spam_dataset.csv"
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")

    # Load dataset
    df = pd.read_csv(dataset_path, comment="#")
    print(f"Loaded {len(df)} text samples.")
    print(f"Class distribution:\n{df['label'].value_counts()}")

    # Binary target: 1 for spam/scam, 0 for ham
    df["target"] = df["label"].map(lambda x: 1 if str(x).strip().lower() == "spam" else 0)

    # Preprocess text
    print("Preprocessing text samples using NLP pipeline...")
    df["cleaned_text"] = df["text"].apply(clean_text_for_nlp)

    # Train / Test split (stratified, test_size=0.25)
    X_train, X_test, y_train, y_test, cat_train, cat_test = train_test_split(
        df["cleaned_text"],
        df["target"],
        df["category"],
        test_size=0.25,
        random_state=42,
        stratify=df["target"]
    )
    print(f"Training set: {len(X_train)} samples | Test set: {len(X_test)} samples")

    # TF-IDF Vectorization
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=2500,
        sublinear_tf=True
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # Candidate 1: Multinomial Naive Bayes
    mnb = MultinomialNB(alpha=0.5)
    mnb.fit(X_train_vec, y_train)
    y_pred_mnb = mnb.predict(X_test_vec)
    f1_mnb = f1_score(y_test, y_pred_mnb, zero_division=0)

    # Candidate 2: Logistic Regression
    lr = LogisticRegression(C=1.0, max_iter=500, random_state=42)
    lr.fit(X_train_vec, y_train)
    y_pred_lr = lr.predict(X_test_vec)
    f1_lr = f1_score(y_test, y_pred_lr, zero_division=0)

    print(f"\nModel Comparison on Held-Out Test Set:")
    print(f" - Multinomial Naive Bayes F1: {f1_mnb:.4f}")
    print(f" - Logistic Regression F1:    {f1_lr:.4f}")

    # Select best model
    if f1_lr >= f1_mnb:
        best_model = lr
        best_name = "Logistic Regression"
        y_pred = y_pred_lr
        y_prob = lr.predict_proba(X_test_vec)[:, 1]
    else:
        best_model = mnb
        best_name = "Multinomial Naive Bayes"
        y_pred = y_pred_mnb
        y_prob = mnb.predict_proba(X_test_vec)[:, 1]

    print(f"\nSelected Model: {best_name}")

    # Comprehensive Evaluation Metrics
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    report = classification_report(y_test, y_pred, target_names=["Ham", "Spam/Scam"], output_dict=True, zero_division=0)

    print("\nEvaluation Results on Test Set:")
    print(f" - Accuracy:  {acc:.4f}")
    print(f" - Precision: {prec:.4f}")
    print(f" - Recall:    {rec:.4f}")
    print(f" - F1-Score:  {f1:.4f}")
    print(f" - Confusion Matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}")

    # Save artifacts
    artifacts_dir = ROOT_DIR / "ml" / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = ROOT_DIR / "ml" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    model_file = artifacts_dir / "text_classifier.joblib"
    vec_file = artifacts_dir / "text_vectorizer.joblib"
    joblib.dump(best_model, model_file)
    joblib.dump(vectorizer, vec_file)

    # Save detailed evaluation report
    report_data = {
        "model_type": best_name,
        "dataset": "SMS Spam Baseline + Supplementary Indian Scam Vectors v1.0.0",
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

    with open(reports_dir / "text_model_report.json", "w") as f:
        json.dump(report_data, f, indent=2)

    print(f"Model saved to: {model_file}")
    print(f"Vectorizer saved to: {vec_file}")
    print(f"Evaluation report saved to: {reports_dir / 'text_model_report.json'}")
    return report_data


if __name__ == "__main__":
    train_text_classifier()
