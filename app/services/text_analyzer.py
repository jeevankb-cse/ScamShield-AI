import re
from typing import Dict, Any, List

from app.utils.text_preprocessing import (
    extract_urls,
    extract_upi_ids,
    extract_phones,
    extract_amounts,
    sanitize_for_preview,
)
from app.ml.text_predictor import predict_text_scam
from app.services.risk_engine import compute_composite_risk
from app.services.explanation_engine import build_explanation, build_recommendations

# Threat & deception pattern matching
URGENCY_PATTERNS = [
    (r"\b(?:within\s*(?:[0-9]{1,2}\s*(?:hours?|hrs?|mins?|minutes?)|today|24\s*hours?))\b", "Strict artificial deadline enforced", "high"),
    (r"\b(?:immediately|urgent(?:ly)?|at once|right now|without delay)\b", "High urgency pressure tactic", "medium"),
    (r"\b(?:blocked|suspended|terminated|deactivated|disconnected|frozen)\b", "Threat of service/account termination", "high"),
    (r"\b(?:legal action|court notice|penalty|fined?|fir|police warrant)\b", "Coercive legal or punitive threats", "critical"),
    (r"\b(?:digital arrest)\b", "Digital arrest threat detected", "critical"),
    (r"\b(?:cbi|narcotics control|customs officer|cyber crime cell|money laundering)\b", "Law enforcement / federal agency impersonation", "critical"),
]

FINANCIAL_PATTERNS = [
    (r"\b(?:enter\s*(?:your\s*)?(?:upi\s*)?pin|provide\s*pin|pin\s*required\s*to\s*receive)\b", "Soliciting UPI PIN to receive money (classic UPI fraud)", "critical"),
    (r"\b(?:share\s*otp|send\s*otp|forward\s*otp|tell\s*otp|verification\s*code)\b", "Direct OTP / Verification credential harvesting", "critical"),
    (r"\b(?:lottery|lucky winner|kbc|won rs|crorepati|prize money)\b", "Lottery or unearned prize claim lure", "high"),
    (r"\b(?:cashback|scratch card|reward points|claim gift)\b", "Cashback reward lure", "high"),
    (r"\b(?:pre-approved loan|instant loan|no cibil|zero cibil)\b", "Predatory unverified loan solicitation", "high"),
    (r"\b(?:part-time job|earn rs|youtube like|telegram task|wfh job)\b", "Unsolicited task-based work-from-home lure", "high"),
    (r"\b(?:electricity power will be disconnected|power cut tonight)\b", "Electricity bill disconnection panic lure", "high"),
]


def analyze_text_message(raw_text: str) -> Dict[str, Any]:
    """Comprehensive scanner for SMS, WhatsApp, and chat text."""
    if not raw_text or not raw_text.strip():
        return {
            "success": False,
            "error": "Message text cannot be empty."
        }

    evidence: List[Dict[str, Any]] = []

    # 1. Structural extractions
    urls = extract_urls(raw_text)
    upi_ids = extract_upi_ids(raw_text)
    phones = extract_phones(raw_text)
    amounts = extract_amounts(raw_text)

    if urls:
        evidence.append({
            "evidence_type": "url",
            "evidence_description": f"Embedded external link detected: {', '.join(urls[:3])}",
            "severity": "high" if any(not u.startswith("https") for u in urls) else "medium"
        })

    if upi_ids:
        evidence.append({
            "evidence_type": "upi",
            "evidence_description": f"Unverified UPI payment handle detected: {', '.join(upi_ids)}",
            "severity": "high"
        })

    # 2. Rule-based linguistic patterns
    lower = raw_text.lower()

    for pattern, desc, sev in URGENCY_PATTERNS:
        if re.search(pattern, lower):
            evidence.append({
                "evidence_type": "urgency",
                "evidence_description": desc,
                "severity": sev
            })

    for pattern, desc, sev in FINANCIAL_PATTERNS:
        if re.search(pattern, lower):
            evidence.append({
                "evidence_type": "financial_lure",
                "evidence_description": desc,
                "severity": sev
            })

    # 3. ML Model prediction
    ml_result = predict_text_scam(raw_text)
    base_ml_prob = ml_result.get("raw_probability", 0.0)
    primary_category = ml_result.get("primary_category", "Phishing attacks")

    # 4. Composite Risk Computation
    risk_data = compute_composite_risk(
        base_ml_prob=base_ml_prob,
        rule_evidence=evidence,
        input_type="SMS / WhatsApp message",
        primary_category=primary_category
    )

    # 5. Explanations & Recommendations
    explanation = build_explanation(
        input_type="SMS / WhatsApp message",
        risk_level=risk_data["risk_level"],
        category=primary_category,
        evidence=evidence,
        risk_score=risk_data["risk_score"]
    )
    recommendations = build_recommendations(primary_category, risk_data["risk_level"])

    return {
        "success": True,
        "input_type": "message",
        "input_preview": sanitize_for_preview(raw_text),
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
            "urls": urls,
            "upi_ids": upi_ids,
            "phone_numbers": phones,
            "amounts": amounts,
        },
        "ml_details": {
            "model_available": ml_result.get("model_available", False),
            "raw_scam_probability": round(base_ml_prob, 4),
            "candidate_categories": ml_result.get("candidate_categories", [])
        }
    }
