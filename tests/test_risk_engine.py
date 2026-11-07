from app.services.risk_engine import calculate_risk_level, compute_composite_risk
from app.services.explanation_engine import build_explanation, build_recommendations


def test_risk_level_banding():
    assert calculate_risk_level(15) == "Low Risk"
    assert calculate_risk_level(29) == "Low Risk"
    assert calculate_risk_level(30) == "Medium Risk"
    assert calculate_risk_level(59) == "Medium Risk"
    assert calculate_risk_level(60) == "High Risk"
    assert calculate_risk_level(79) == "High Risk"
    assert calculate_risk_level(80) == "Very High Risk"
    assert calculate_risk_level(100) == "Very High Risk"


def test_composite_risk_critical_override():
    evidence = [
        {"evidence_type": "otp", "evidence_description": "OTP harvesting", "severity": "critical"},
        {"evidence_type": "impersonation", "evidence_description": "CBI impersonation", "severity": "critical"}
    ]
    res = compute_composite_risk(
        base_ml_prob=0.3,
        rule_evidence=evidence,
        input_type="SMS",
        primary_category="Digital arrest threats"
    )
    assert res["risk_score"] >= 85
    assert res["risk_level"] == "Very High Risk"


def test_recommendations_consistency():
    recs_low = build_recommendations("Legitimate communication", "Low Risk")
    assert len(recs_low) > 0

    recs_upi = build_recommendations("UPI payment fraud", "High Risk")
    assert any("PIN" in r for r in recs_upi)

    recs_arrest = build_recommendations("Digital arrest threats", "Very High Risk")
    assert any("1930" in r or "never conduct" in r.lower() for r in recs_arrest)
