from app.services.url_analyzer import analyze_url_target
from app.utils.validators import validate_url_input, is_ssrf_safe_hostname


def test_raw_ip_url_detection():
    url = "http://192.168.1.100/sbi-netbanking-login/index.php"
    res = analyze_url_target(url)

    assert res["success"] is True
    assert res["risk_score"] >= 60
    assert any("raw IP" in ev["evidence_description"] for ev in res["evidence"])


def test_suspicious_tld_and_phish_keywords():
    url = "http://paytm-cashback-reward-claim.xyz/verify.html"
    res = analyze_url_target(url)

    assert res["success"] is True
    assert res["risk_score"] >= 50
    assert "features" in res
    assert res["features"]["has_suspicious_tld"] == 1


def test_ssrf_protection_blocked():
    assert is_ssrf_safe_hostname("127.0.0.1") is False
    assert is_ssrf_safe_hostname("localhost") is False
    assert is_ssrf_safe_hostname("169.254.169.254") is False
    assert is_ssrf_safe_hostname("google.com") is True


def test_legitimate_url():
    url = "https://www.sbi.co.in"
    res = analyze_url_target(url)

    assert res["success"] is True
    assert res["risk_score"] < 30
