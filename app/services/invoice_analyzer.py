import re
from pathlib import Path
from typing import Dict, Any, List, Optional

from app.services.pdf_analyzer import extract_pdf_content
from app.services.risk_engine import compute_composite_risk
from app.services.explanation_engine import build_explanation, build_recommendations

# GSTIN Regex: 2 digits state code, 5 uppercase letters PAN, 4 digits, 1 letter, 1 entity code, 'Z', 1 check character
GSTIN_REGEX = re.compile(r'\b([0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1})\b')

# Bank Account & IFSC regex
IFSC_REGEX = re.compile(r'\b([A-Z]{4}0[A-Z0-9]{6})\b')
ACCOUNT_REGEX = re.compile(r'\b(?:a\/c|account\s*(?:no|number)?)\s*[:#]?\s*([0-9]{9,18})\b', re.IGNORECASE)

# Invoice Number regex (requires separator to avoid capturing label words)
INVOICE_NUM_REGEX = re.compile(r'\b(?:invoice\s*(?:no\.?|#|num\.?|number)?)\s*[:#]\s*([A-Za-z0-9_\-\/]{3,30})\b', re.IGNORECASE)

# Date regex
DATE_REGEX = re.compile(r'\b([0-9]{1,2}[-\/\.][0-9]{1,2}[-\/\.][0-9]{2,4})\b')

# Amount extraction patterns
TOTAL_REGEX = re.compile(r'\b(?:grand\s*total|total\s*amount|net\s*payable|total)\s*[:₹\s]*(?:rs\.?|inr|₹)?\s*([0-9,]+(?:\.[0-9]{1,2})?)\b', re.IGNORECASE)
SUBTOTAL_REGEX = re.compile(r'\b(?:sub[\s\-]*total|taxable\s*(?:value|amount))\s*[:₹\s]*(?:rs\.?|inr|₹)?\s*([0-9,]+(?:\.[0-9]{1,2})?)\b', re.IGNORECASE)
TAX_REGEX = re.compile(r'\b(?:tax\s*amount|cgst\s*\+\s*sgst|igst|total\s*tax|gst\s*amount)\s*[:₹\s]*(?:rs\.?|inr|₹)?\s*([0-9,]+(?:\.[0-9]{1,2})?)\b', re.IGNORECASE)

# Suspicious change keywords
BANK_CHANGE_KEYWORDS = [
    "account details updated", "new bank account", "updated bank details",
    "please note new ifsc", "new remittance instructions", "transfer to new a/c",
    "temporary account", "change of banking", "bank details have changed"
]

URGENCY_KEYWORDS = [
    "pay within 24 hours", "immediate settlement required", "overdue penalty",
    "legal consequence", "pay immediately", "stop delivery"
]


def _parse_amount(amt_str: Optional[str]) -> Optional[float]:
    """Parse comma-separated amount string into float."""
    if not amt_str:
        return None
    try:
        clean = amt_str.replace(",", "").strip()
        return float(clean)
    except Exception:
        return None


def extract_invoice_fields(text: str) -> Dict[str, Any]:
    """Extract standard commercial invoice fields via regex."""
    gstin_matches = GSTIN_REGEX.findall(text)
    ifsc_matches = IFSC_REGEX.findall(text)
    acct_matches = ACCOUNT_REGEX.findall(text)
    inv_num_match = INVOICE_NUM_REGEX.search(text)
    date_matches = DATE_REGEX.findall(text)

    # Amounts
    tot_match = TOTAL_REGEX.search(text)
    sub_match = SUBTOTAL_REGEX.search(text)
    tax_match = TAX_REGEX.search(text)

    total_val = _parse_amount(tot_match.group(1)) if tot_match else None
    subtotal_val = _parse_amount(sub_match.group(1)) if sub_match else None
    tax_val = _parse_amount(tax_match.group(1)) if tax_match else None

    return {
        "invoice_number": inv_num_match.group(1) if inv_num_match else None,
        "gstins": list(set(gstin_matches)),
        "ifsc_codes": list(set(ifsc_matches)),
        "bank_accounts": list(set(acct_matches)),
        "dates": date_matches[:3],
        "subtotal": subtotal_val,
        "tax_amount": tax_val,
        "total_amount": total_val,
    }


def analyze_pdf_invoice(
    pdf_path: Path,
    comparison_pdf_path: Optional[Path] = None
) -> Dict[str, Any]:
    """Analyze invoice for structural, arithmetic, and payment modification risks."""
    pdf_data = extract_pdf_content(pdf_path)
    if not pdf_data["success"]:
        return {
            "success": False,
            "error": pdf_data["error"]
        }

    raw_text = pdf_data["full_text"]
    fields = extract_invoice_fields(raw_text)
    lower_text = raw_text.lower()
    evidence: List[Dict[str, Any]] = []

    # 1. Suspicious Bank Detail Alterations (Critical Indicator)
    has_bank_change = any(kw in lower_text for kw in BANK_CHANGE_KEYWORDS)
    if has_bank_change:
        evidence.append({
            "evidence_type": "bank_details_change",
            "evidence_description": "Notification claiming supplier bank account details have been modified",
            "severity": "critical"
        })

    # 2. Urgency and Coercive Settlement Language
    urgency_hits = [kw for kw in URGENCY_KEYWORDS if kw in lower_text]
    if urgency_hits:
        evidence.append({
            "evidence_type": "payment_urgency",
            "evidence_description": f"Aggressive payment deadline or punitive pressure: '{urgency_hits[0]}'",
            "severity": "high"
        })

    # 3. Arithmetic Consistency Check
    subtotal = fields["subtotal"]
    tax = fields["tax_amount"]
    total = fields["total_amount"]
    arithmetic_valid = None

    if subtotal is not None and tax is not None and total is not None:
        expected_total = subtotal + tax
        diff = abs(expected_total - total)
        if diff > 1.50:  # Beyond reasonable fractional rounding
            arithmetic_valid = False
            evidence.append({
                "evidence_type": "arithmetic_mismatch",
                "evidence_description": f"Calculated total (Subtotal {subtotal} + Tax {tax} = {expected_total}) does not match stated Total ({total})",
                "severity": "high"
            })
        else:
            arithmetic_valid = True

    # 4. GSTIN Format Verification
    gstin_found = len(fields["gstins"]) > 0
    if not gstin_found:
        # Note: Do NOT claim missing GSTIN proves fraud
        evidence.append({
            "evidence_type": "gstin_unverified",
            "evidence_description": "No valid 15-character Indian GSTIN detected in document text",
            "severity": "low"
        })

    # 5. Comparison with Previous Legitimate Invoice (if supplied)
    comparison_analysis = None
    if comparison_pdf_path and comparison_pdf_path.exists():
        comp_data = extract_pdf_content(comparison_pdf_path)
        if comp_data["success"]:
            comp_fields = extract_invoice_fields(comp_data["full_text"])
            comparison_analysis = {
                "comparison_invoice_number": comp_fields["invoice_number"],
                "bank_account_match": True,
                "gstin_match": True
            }

            # Check if bank accounts differ
            if fields["bank_accounts"] and comp_fields["bank_accounts"]:
                if set(fields["bank_accounts"]) != set(comp_fields["bank_accounts"]):
                    comparison_analysis["bank_account_match"] = False
                    evidence.append({
                        "evidence_type": "bank_account_mismatch",
                        "evidence_description": f"Bank account ({', '.join(fields['bank_accounts'])}) does not match previously trusted account ({', '.join(comp_fields['bank_accounts'])})",
                        "severity": "critical"
                    })

            # Check GSTIN continuity
            if fields["gstins"] and comp_fields["gstins"]:
                if set(fields["gstins"]) != set(comp_fields["gstins"]):
                    comparison_analysis["gstin_match"] = False
                    evidence.append({
                        "evidence_type": "gstin_mismatch",
                        "evidence_description": "Supplier GSTIN differs from reference invoice",
                        "severity": "high"
                    })

    # 6. Calculate Composite Risk
    # Hybrid rule-based analyzer: base score computed directly from evidence without pretending to have a black-box model
    base_prob = 0.15
    if any(e["severity"] == "critical" for e in evidence):
        base_prob = 0.85
    elif any(e["severity"] == "high" for e in evidence):
        base_prob = 0.60
    elif len(evidence) == 0:
        base_prob = 0.05

    primary_category = "Fake invoice and supplier payment fraud" if base_prob >= 0.50 else "Legitimate communication"

    risk_data = compute_composite_risk(
        base_ml_prob=base_prob,
        rule_evidence=evidence,
        input_type="PDF invoice",
        primary_category=primary_category
    )

    explanation = build_explanation(
        input_type="PDF invoice",
        risk_level=risk_data["risk_level"],
        category=primary_category,
        evidence=evidence,
        risk_score=risk_data["risk_score"]
    )
    recommendations = build_recommendations("Fake invoice and supplier payment fraud", risk_data["risk_level"])

    return {
        "success": True,
        "input_type": "pdf_invoice",
        "input_preview": f"Invoice: {fields['invoice_number'] or 'N/A'} | Pages: {pdf_data['page_count']}",
        "risk_score": risk_data["risk_score"],
        "risk_level": risk_data["risk_level"],
        "predicted_category": primary_category,
        "confidence": risk_data["confidence"],
        "model_version": "v1.0.0 (Explainable Hybrid Rules)",
        "scan_timestamp": risk_data["scan_timestamp"],
        "explanation": explanation,
        "recommendations": recommendations,
        "evidence": evidence,
        "extracted_fields": {
            "invoice_number": fields["invoice_number"],
            "gstins": fields["gstins"],
            "ifsc_codes": fields["ifsc_codes"],
            "bank_accounts": fields["bank_accounts"],
            "dates": fields["dates"],
            "subtotal": fields["subtotal"],
            "tax_amount": fields["tax_amount"],
            "total_amount": fields["total_amount"],
            "arithmetic_consistent": arithmetic_valid,
        },
        "comparison_report": comparison_analysis,
        "disclaimer": "Predictions are risk assessments based on heuristic textual analysis. Missing fields do NOT constitute proof of fraud."
    }
