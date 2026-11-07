from app.services.text_analyzer import analyze_text_message


def test_scan_fake_kyc_message():
    msg = "Dear customer, your SBI account 4819 is blocked due to missing PAN. Click http://sbi-pan-update.in to verify immediately."
    res = analyze_text_message(msg)

    assert res["success"] is True
    assert res["risk_score"] >= 60  # Should be high / very high risk
    assert res["risk_level"] in ("High Risk", "Very High Risk")
    assert res["predicted_category"] in ("Fake KYC updates", "Bank impersonation", "Phishing attacks")
    assert len(res["evidence"]) > 0
    assert len(res["recommendations"]) > 0


def test_scan_upi_pin_fraud():
    msg = "Congratulations! You have received cashback of Rs 5000. Enter your UPI PIN to receive money in your bank account."
    res = analyze_text_message(msg)

    assert res["success"] is True
    assert res["risk_score"] >= 60
    assert any("UPI" in ev["evidence_description"] or "PIN" in ev["evidence_description"] for ev in res["evidence"])


def test_scan_digital_arrest_threat():
    msg = "CBI Police Notice: Your Aadhaar is implicated in money laundering. You are under Digital Arrest. Join Skype call immediately."
    res = analyze_text_message(msg)

    assert res["success"] is True
    assert res["risk_score"] >= 80
    assert res["risk_level"] == "Very High Risk"
    assert "Digital arrest threats" in res["predicted_category"] or "Phishing" in res["predicted_category"]


def test_scan_legitimate_message():
    msg = "Hey, are we still meeting today at the office for the quarterly team review at 3 PM?"
    res = analyze_text_message(msg)

    assert res["success"] is True
    assert res["risk_score"] < 30
    assert res["risk_level"] == "Low Risk"
