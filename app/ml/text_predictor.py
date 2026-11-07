import logging
from typing import Tuple, Dict, Any, List
from app.ml.model_loader import model_registry
from app.utils.text_preprocessing import clean_text_for_nlp

logger = logging.getLogger(__name__)

# Category keyword fingerprints for India-specific scam categories
CATEGORY_SIGNALS = {
    "Digital arrest threats": [
        "digital arrest", "cbi", "narcotics", "customs", "money laundering", "police warrant",
        "arrest warrant", "skype call", "video call arrest", "supreme court order", "dcp"
    ],
    "Fake KYC updates": [
        "kyc", "pan card", "pan update", "missing pan", "pan", "aadhaar", "account blocked", "account suspended", "deactivated",
        "re-kyc", "sim block", "update pan", "verify documents", "wallet kyc"
    ],
    "UPI payment fraud": [
        "upi pin", "gpay", "phonepe", "paytm", "scratch card", "cashback claim", "receive money",
        "enter pin to receive", "request money", "upi id"
    ],
    "Fake job offers": [
        "work from home", "part-time job", "youtube like", "telegram task", "daily salary",
        "hr recruitment", "shortlisted resume", "earn rs", "per day task", "data entry job"
    ],
    "Loan scams": [
        "pre-approved loan", "instant loan", "zero cibil", "no documents", "loan apk",
        "sanctioned amount", "disbursal in 5 minutes", "quick cash loan"
    ],
    "Lottery and prize scams": [
        "kbc", "lottery", "lucky winner", "won rs", "cheque prize", "car winner",
        "crorepati", "congratulations won", "claim prize"
    ],
    "Courier and delivery scams": [
        "india post", "parcel", "delivery failed", "reschedule package", "fedex", "bluedart",
        "customs duty", "address incomplete", "courier tracking"
    ],
    "Refund scams": [
        "tax refund", "income tax", "refund approved", "electricity refund", "claim refund",
        "overpayment", "refund department"
    ],
    "Government impersonation": [
        "income tax department", "rbi", "ministry", "aadhaar authority", "uidai", "cyber cell",
        "pib", "pm-kisan", "subsidies"
    ],
    "Bank impersonation": [
        "sbi", "hdfc", "icici", "axis bank", "pnb", "bank of baroda", "netbanking", "debit card"
    ],
    "OTP and PIN harvesting": [
        "share otp", "verification code", "one time password", "tell pin", "enter password",
        "confirm 2fa", "security code"
    ],
    "Phishing attacks": [
        "verify identity", "security alert", "suspicious login", "password reset", "unauthorized access",
        "confirm account", "click link to secure"
    ]
}


def predict_text_scam(raw_text: str) -> Dict[str, Any]:
    """Perform ML classification and semantic category association on input text."""
    model = model_registry.text_model
    vectorizer = model_registry.text_vectorizer

    if model is None or vectorizer is None:
        return {
            "model_available": False,
            "raw_probability": 0.0,
            "predicted_label": 0,
            "candidate_categories": [],
            "error": "Text classification model or vectorizer not loaded."
        }

    cleaned = clean_text_for_nlp(raw_text)
    if not cleaned.strip():
        return {
            "model_available": True,
            "raw_probability": 0.05,
            "predicted_label": 0,
            "candidate_categories": ["Legitimate communication"],
            "error": None
        }

    vec = vectorizer.transform([cleaned])
    try:
        probabilities = model.predict_proba(vec)[0]
        # Class 1 is Spam/Scam
        prob_scam = float(probabilities[1]) if len(probabilities) > 1 else 0.5
        predicted_label = int(model.predict(vec)[0])
    except Exception as e:
        logger.error(f"Prediction failure: {e}")
        prob_scam = 0.5
        predicted_label = 1

    # Detect categories based on semantic signals
    lower_text = raw_text.lower()
    matched_categories: List[Tuple[str, int]] = []

    for cat_name, keywords in CATEGORY_SIGNALS.items():
        score = sum(1 for kw in keywords if kw in lower_text)
        if score > 0:
            matched_categories.append((cat_name, score))

    matched_categories.sort(key=lambda x: x[1], reverse=True)
    candidate_cats = [c[0] for c in matched_categories]

    if not candidate_cats:
        if prob_scam > 0.5:
            candidate_cats = ["Phishing attacks"]
        else:
            candidate_cats = ["Legitimate communication"]

    return {
        "model_available": True,
        "raw_probability": prob_scam,
        "predicted_label": predicted_label,
        "candidate_categories": candidate_cats,
        "primary_category": candidate_cats[0],
        "error": None
    }
