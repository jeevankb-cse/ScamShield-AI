import datetime
from typing import Dict, Any, List

# Risk display bands
# 0–29: Low Risk
# 30–59: Medium Risk
# 60–79: High Risk
# 80–100: Very High Risk

MODEL_VERSION = "v1.0.0"


def calculate_risk_level(score: int) -> str:
    """Map integer risk score (0-100) to standard severity band."""
    if score >= 80:
        return "Very High Risk"
    elif score >= 60:
        return "High Risk"
    elif score >= 30:
        return "Medium Risk"
    return "Low Risk"


def compute_composite_risk(
    base_ml_prob: float,
    rule_evidence: List[Dict[str, Any]],
    input_type: str,
    primary_category: str
) -> Dict[str, Any]:
    """
    Carefully combine calibrated ML model outputs and rule-based indicators.
    Avoids treating raw classifier probabilities as fully calibrated.
    """
    # Base score from ML: scale 0.0 - 1.0 to 0 - 55
    ml_contribution = min(55.0, base_ml_prob * 55.0)

    # Calculate evidence impact
    evidence_score = 0.0
    critical_count = 0
    high_count = 0

    for ev in rule_evidence:
        sev = ev.get("severity", "medium").lower()
        if sev == "critical":
            evidence_score += 25.0
            critical_count += 1
        elif sev == "high":
            evidence_score += 15.0
            high_count += 1
        elif sev == "medium":
            evidence_score += 8.0
        else:
            evidence_score += 3.0

    # Critical override rule: if critical phishing indicators exist (e.g. OTP harvesting or digital arrest), ensure High or Very High
    raw_score = ml_contribution + evidence_score

    if critical_count >= 2:
        raw_score = max(85.0, raw_score)
    elif critical_count >= 1:
        raw_score = max(68.0, raw_score)
    elif high_count >= 2:
        raw_score = max(62.0, raw_score)

    final_score = int(min(100.0, max(0.0, round(raw_score))))
    risk_level = calculate_risk_level(final_score)

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "predicted_category": primary_category,
        "input_type": input_type,
        "scan_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "model_version": MODEL_VERSION,
        "confidence": round(min(0.99, max(0.10, base_ml_prob)), 3),
    }
