from typing import List, Dict, Any

# Safety recommendations catalog tailored to Indian digital fraud threats
STANDARD_RECOMMENDATIONS = {
    "Digital arrest threats": [
        "Remember that Indian police, CBI, ED, and customs NEVER conduct 'digital arrest' or interrogate citizens over Skype/WhatsApp video calls.",
        "Hang up immediately and block the caller. Do NOT transfer funds under any pretexts or 'clearance deposits'.",
        "Report the call immediately to the National Cyber Crime Portal (cybercrime.gov.in) or call helpline 1930."
    ],
    "Fake KYC updates": [
        "Do NOT click any SMS or email links requesting KYC, PAN or Aadhaar re-verification.",
        "Banks, wallets and telecom providers never ask for KYC updates through third-party bit.ly or unofficial URLs.",
        "Visit your bank branch directly or use only the verified official mobile banking application."
    ],
    "UPI payment fraud": [
        "Remember the cardinal UPI rule: You NEVER need to enter your UPI PIN to RECEIVE money or claim cashbacks.",
        "Entering your UPI PIN always DEBITS funds from your bank account.",
        "Decline any incoming collect requests or QR codes sent by unknown individuals."
    ],
    "Fake job offers": [
        "Legitimate employers never demand payment for interview registration, training kits, or software packages.",
        "Beware of Telegram/WhatsApp schemes offering high daily pay for liking YouTube videos or submitting fake hotel reviews.",
        "Verify job vacancies directly on the company's verified corporate careers portal."
    ],
    "Loan scams": [
        "Never download loan APKs from unofficial links, SMS, or Telegram channels.",
        "Check whether the lending app is an RBI-registered NBFC before providing access to your contacts and photo gallery.",
        "Report predatory blackmail loan apps to the local cyber cell and RBI Sachet portal."
    ],
    "Lottery and prize scams": [
        "You cannot win a lottery or prize in a contest you never entered.",
        "Never pay 'tax clearance', 'processing fees' or 'conversion charges' to claim lottery winnings.",
        "Block the sender and warn family members about impersonators using celebrity logos."
    ],
    "Refund scams": [
        "Income tax and utility refunds are credited directly to your validated bank account, never via external links.",
        "Never enter your debit card CVV, expiry date, or NetBanking password on refund claim portals.",
        "Verify refund status directly at incometax.gov.in."
    ],
    "Courier and delivery scams": [
        "India Post, FedEx and BlueDart do not charge small fees (e.g. ₹5 or ₹25) via random SMS links for redelivery.",
        "Check tracking numbers only on official delivery websites.",
        "Do not provide personal or credit card details on parcel reschedule forms."
    ],
    "OTP and PIN harvesting": [
        "Never share OTPs, passwords, or MPINs with anyone—including individuals claiming to be bank managers.",
        "No bank employee or police officer is authorized to request your one-time password.",
        "If an OTP was entered unintentionally, immediately freeze your account via your bank's toll-free number."
    ],
    "Malicious URLs": [
        "Do not visit the URL or enter login credentials, passwords, or personal identity numbers.",
        "Examine the domain carefully for typo-squatting, raw IP addresses, and suspicious subdomains.",
        "Keep your browser security filters enabled and report suspicious URLs to CERT-In (incident@cert-in.org.in)."
    ],
    "Fake invoice and supplier payment fraud": [
        "Always execute out-of-band phone verification using previously verified phone numbers before changing vendor bank accounts.",
        "Verify vendor GSTIN status and legal name on the official GST portal (services.gst.gov.in).",
        "Subject any invoice with urgent payment demands or altered account details to strict secondary managerial signoff."
    ],
    "Legitimate communication": [
        "The scanned content does not display overt deceptive indicators, credential theft lures, or malicious patterns.",
        "Maintain standard cybersecurity hygiene: verify sender addresses on incoming requests.",
        "Keep your software and multi-factor authentication active."
    ]
}


def build_explanation(
    input_type: str,
    risk_level: str,
    category: str,
    evidence: List[Dict[str, Any]],
    risk_score: int
) -> str:
    """Generate a cohesive narrative explaining detected signals and threat risk."""
    if risk_score < 30:
        return (
            f"The analyzed {input_type} returned a low risk score of {risk_score}/100. "
            "No known malicious URLs, coercive urgency triggers, or credential harvesting signatures were observed. "
            "This communication appears consistent with normal legitimate interaction, though routine caution is always advised."
        )

    critical_items = [e['evidence_description'] for e in evidence if e.get('severity') == 'critical']
    high_items = [e['evidence_description'] for e in evidence if e.get('severity') == 'high']

    parts = [
        f"This {input_type} has been assessed as {risk_level} ({risk_score}/100) under the category '{category}'."
    ]

    if critical_items:
        parts.append(f"Critical warning signs identified: {'; '.join(critical_items)}.")
    elif high_items:
        parts.append(f"Significant warning indicators detected: {'; '.join(high_items)}.")

    parts.append(
        "These patterns closely resemble tactics utilized in social engineering and financial fraud. "
        "Exercise extreme caution and do not disclose sensitive details or transfer money."
    )

    return " ".join(parts)


def build_recommendations(category: str, risk_level: str) -> List[str]:
    """Retrieve tailored safety action points for the given category."""
    if risk_level == "Low Risk":
        return STANDARD_RECOMMENDATIONS["Legitimate communication"]

    return STANDARD_RECOMMENDATIONS.get(
        category,
        [
            "Do not click links, download attachments, or share OTPs.",
            "Verify the authenticity of the sender through official channels.",
            "Report fraudulent interactions to the national cybercrime helpline (1930)."
        ]
    )
