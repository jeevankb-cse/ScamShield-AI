import ipaddress
import re
from typing import Dict, Any, List
from urllib.parse import urlparse

from app.utils.validators import validate_url_input, is_ssrf_safe_hostname
from app.ml.url_predictor import predict_url_phishing
from app.services.risk_engine import compute_composite_risk
from app.services.explanation_engine import build_explanation, build_recommendations

SUSPICIOUS_TLDS = {".xyz", ".top", ".buzz", ".club", ".tk", ".ml", ".ga", ".cc", ".online", ".site", ".work", ".info"}
HIGH_RISK_KEYWORDS = ["sbi", "hdfc", "icici", "paytm", "gpay", "phonepe", "kyc", "verify", "login", "refund", "arrest", "cbi"]


def analyze_url_target(target_url: str) -> Dict[str, Any]:
    """Analyze URL structure and lexical features without fetching or executing."""
    valid, result_or_err = validate_url_input(target_url)
    if not valid:
        return {
            "success": False,
            "error": result_or_err
        }

    normalized_url = result_or_err
    parsed = urlparse(normalized_url)
    hostname = parsed.hostname or ""

    evidence: List[Dict[str, Any]] = []

    # 1. SSRF Safety Check & IP Literal Detection
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
        evidence.append({
            "evidence_type": "raw_ip_hostname",
            "evidence_description": f"URL uses raw IP address ({hostname}) instead of a registered domain name",
            "severity": "critical"
        })
    except ValueError:
        is_ip = False

    # Check for private or internal address
    if not is_ssrf_safe_hostname(hostname):
        evidence.append({
            "evidence_type": "ssrf_risk",
            "evidence_description": "Target hostname points to private/loopback/cloud metadata address",
            "severity": "critical"
        })

    # 2. Structural checks
    if len(normalized_url) > 75:
        evidence.append({
            "evidence_type": "excessive_length",
            "evidence_description": f"Abnormally long URL string ({len(normalized_url)} characters)",
            "severity": "medium"
        })

    # Excessive subdomains
    domain_parts = hostname.split(".")
    if not is_ip and len(domain_parts) > 3:
        evidence.append({
            "evidence_type": "excessive_subdomains",
            "evidence_description": f"High number of subdomain levels ({len(domain_parts) - 2}) which may conceal true destination",
            "severity": "high"
        })

    # Suspicious TLD
    has_suspicious_tld = any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
    if has_suspicious_tld:
        evidence.append({
            "evidence_type": "suspicious_tld",
            "evidence_description": f"Domain utilizes a high-abuse top-level domain ({'.' + hostname.split('.')[-1]})",
            "severity": "high"
        })

    # Misleading brand keywords in untrusted domain
    matched_brands = [b for b in HIGH_RISK_KEYWORDS if b in normalized_url.lower()]
    if matched_brands and not any(hostname.endswith(safe) for safe in ["sbi.co.in", "hdfcbank.com", "icicibank.com", "paytm.com", "gov.in"]):
        evidence.append({
            "evidence_type": "brand_typosquatting",
            "evidence_description": f"Deceptive security/brand terms detected in path/subdomain: {', '.join(matched_brands)}",
            "severity": "critical" if any(b in hostname for b in ["sbi", "hdfc", "paytm", "cbi"]) else "high"
        })

    # HTTPS check
    if parsed.scheme.lower() != "https":
        evidence.append({
            "evidence_type": "unencrypted_transport",
            "evidence_description": "URL uses insecure HTTP protocol rather than HTTPS",
            "severity": "medium"
        })

    # 3. Model Prediction
    model_res = predict_url_phishing(normalized_url)
    raw_ml_prob = model_res.get("raw_probability", 0.0)

    # 4. Composite Risk Computation
    risk_data = compute_composite_risk(
        base_ml_prob=raw_ml_prob,
        rule_evidence=evidence,
        input_type="Website URL",
        primary_category="Malicious URLs"
    )

    explanation = build_explanation(
        input_type="Website URL",
        risk_level=risk_data["risk_level"],
        category="Malicious URLs",
        evidence=evidence,
        risk_score=risk_data["risk_score"]
    )
    recommendations = build_recommendations("Malicious URLs", risk_data["risk_level"])

    return {
        "success": True,
        "input_type": "url",
        "url": normalized_url,
        "input_preview": normalized_url[:120],
        "hostname": hostname,
        "risk_score": risk_data["risk_score"],
        "risk_level": risk_data["risk_level"],
        "predicted_category": "Malicious URLs" if risk_data["risk_score"] >= 30 else "Legitimate communication",
        "confidence": risk_data["confidence"],
        "model_version": risk_data["model_version"],
        "scan_timestamp": risk_data["scan_timestamp"],
        "explanation": explanation,
        "recommendations": recommendations,
        "evidence": evidence,
        "features": model_res.get("features", {}),
        "ml_details": {
            "model_available": model_res.get("model_available", False),
            "raw_probability": round(raw_ml_prob, 4)
        }
    }
