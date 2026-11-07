from app.services.email_analyzer import analyze_email_content


def test_spoofed_bank_email():
    sender = "security@sbi-bank-verify.xyz"
    subject = "Action Required: Your NetBanking is Blocked within 24 hours"
    body = "Dear Customer, please verify your PAN card and debit card CVV at http://sbi-verify-portal.net/login"

    res = analyze_email_content(sender, subject, body)
    assert res["success"] is True
    assert res["risk_score"] >= 60
    assert any("domain mimics" in ev["evidence_description"].lower() or "typosquatting" in ev["evidence_type"] for ev in res["evidence"])


def test_free_webmail_authority_spoof():
    sender = "officer.incometax@gmail.com"
    subject = "Income Tax Department: Immediate Tax Refund of Rs 35,000"
    body = "Click here to claim your refund before it expires tonight."

    res = analyze_email_content(sender, subject, body)
    assert res["success"] is True
    assert res["risk_score"] >= 60
    assert any("free webmail" in ev["evidence_description"].lower() for ev in res["evidence"])


def test_legitimate_newsletter_email():
    sender = "newsletter@github.com"
    subject = "Your GitHub daily digest"
    body = "Here are the top trending open source repositories and issues for your starred projects."

    res = analyze_email_content(sender, subject, body)
    assert res["success"] is True
    assert res["risk_score"] < 40
