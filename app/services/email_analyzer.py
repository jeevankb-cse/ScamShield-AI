import re
from typing import Dict, Any, List

from app.utils.text_preprocessing import extract_urls, sanitize_for_preview, clean_text_for_nlp
from app.ml.model_loader import model_registry
from app.ml.text_predictor import predict_text_scam
from app.services.risk_engine import compute_composite_risk
from app.services.explanation_engine import build_explanation, build_recommendations

LEGITIMATE_BANK_GOV_DOMAINS = {
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "pnbindia.in",
    "incometax.gov.in", "rbi.org.in", "uidai.gov.in", "cybercrime.gov.in", "gov.in", "nic.in"
}

FREE_MAIL_PROVIDERS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "rediffmail.com", "mail.com"}

SUSPICIOUS_SENDER_KEYWORDS = ["bank", "support", "security", "kyc", "tax", "police", "refund", "admin", "service", "verify"]


def analyze_email_content(sender: str, subject: str, body: str) -> Dict[str, Any]:
    """Inspect email metadata, headers, subject line, and message body for phishing."""
    combined_text = f"From: {sender}\nSubject: {subject}\n\n{body}"
    evidence: List[Dict[str, Any]] = []

    sender_clean = sender.strip().lower() if sender else ""
    subject_clean = subject.strip() if subject else ""
    body_clean = body.strip() if body else ""

    # 1. Analyze Sender Domain and Patterns
    sender_domain = ""
    if "@" in sender_clean:
        sender_domain = sender_clean.split("@")[-1]

    # Check for free webmail impersonation
    is_free_mail = sender_domain in FREE_MAIL_PROVIDERS
    has_authority_subject = any(kw in (subject_clean + " " + body_clean).lower() for kw in ["bank", "sbi", "hdfc", "income tax", "rbi", "court", "cbi"])

    if is_free_mail and has_authority_subject:
        evidence.append({
            "evidence_type": "sender_spoofing",
            "evidence_description": f"Official institution impersonated using free webmail service (@{sender_domain})",
            "severity": "critical"
        })

    # Check for lookalike / deceptive domains
    if any(bank in sender_domain for bank in ["sbi", "hdfc", "icici", "axis", "incometax", "paytm"]) and sender_domain not in LEGITIMATE_BANK_GOV_DOMAINS:
        evidence.append({
            "evidence_type": "domain_typosquatting",
            "evidence_description": f"Sender domain (@{sender_domain}) mimics official enterprise domain",
            "severity": "critical"
        })

    # 2. Extract and inspect URLs
    urls = extract_urls(body_clean)
    if urls:
        evidence.append({
            "evidence_type": "email_links",
            "evidence_description": f"{len(urls)} link(s) embedded in email body",
            "severity": "high" if any("http://" in u or ".xyz" in u or ".top" in u for u in urls) else "medium"
        })

    # 3. Urgency and Threat Analysis in Email Subject/Body
    full_email_text = f"{subject_clean} {body_clean}".lower()
    if re.search(r"\b(?:within\s*24\s*hours?|immediately|urgent|account\s*blocked|suspended)\b", full_email_text):
        evidence.append({
            "evidence_type": "urgency_coercion",
            "evidence_description": "Artificial deadline pressure in email content",
            "severity": "high"
        })

    if re.search(r"\b(?:refund|tax\s*return|credited\s*rs|won\s*prize|lottery)\b", full_email_text):
        evidence.append({
            "evidence_type": "financial_lure",
            "evidence_description": "Unsolicited monetary incentive or refund claim lure",
            "severity": "high"
        })

    # 4. ML Model Evaluation
    model = model_registry.email_model
    vec = model_registry.email_vectorizer

    if model is not None and vec is not None:
        nlp_ready = clean_text_for_nlp(combined_text)
        X_vec = vec.transform([nlp_ready])
        try:
            probs = model.predict_proba(X_vec)[0]
            ml_prob = float(probs[1]) if len(probs) > 1 else 0.5
        except Exception:
            ml_prob = 0.5
    else:
        # Fallback to general text predictor
        text_pred = predict_text_scam(combined_text)
        ml_prob = text_pred.get("raw_probability", 0.0)

    # Determine primary scam category
    text_pred = predict_text_scam(combined_text)
    primary_category = text_pred.get("primary_category", "Phishing attacks")

    # 5. Composite Risk Computation
    risk_data = compute_composite_risk(
        base_ml_prob=ml_prob,
        rule_evidence=evidence,
        input_type="Email message",
        primary_category=primary_category
    )

    explanation = build_explanation(
        input_type="Email message",
        risk_level=risk_data["risk_level"],
        category=primary_category,
        evidence=evidence,
        risk_score=risk_data["risk_score"]
    )
    recommendations = build_recommendations(primary_category, risk_data["risk_level"])

    return {
        "success": True,
        "input_type": "email",
        "sender": sender,
        "subject": subject,
        "input_preview": sanitize_for_preview(f"From: {sender} | Sub: {subject}"),
        "risk_score": risk_data["risk_score"],
        "risk_level": risk_data["risk_level"],
        "predicted_category": primary_category,
        "confidence": risk_data["confidence"],
        "model_version": risk_data["model_version"],
        "scan_timestamp": risk_data["scan_timestamp"],
        "explanation": explanation,
        "recommendations": recommendations,
        "evidence": evidence,
        "extracted_entities": {
            "sender_domain": sender_domain,
            "urls": urls,
            "is_free_mail": is_free_mail
        },
        "ml_details": {
            "raw_phishing_probability": round(ml_prob, 4),
            "model_version": "v1.0.0"
        }
    }
