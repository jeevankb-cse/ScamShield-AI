import os
import tempfile
from pathlib import Path
import pymupdf  # fitz

from app.services.invoice_analyzer import analyze_pdf_invoice, extract_invoice_fields


def create_sample_pdf(content_text: str) -> Path:
    """Helper to generate a realistic PDF file dynamically for tests."""
    temp_dir = Path(tempfile.mkdtemp())
    pdf_path = temp_dir / "sample_invoice.pdf"

    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((50, 72), content_text, fontsize=11)
    doc.save(str(pdf_path))
    doc.close()
    return pdf_path


def test_invoice_with_bank_change_and_arithmetic_mismatch():
    text = """
    TAX INVOICE
    Invoice Number: INV-2026-9921
    Date: 12-10-2026
    GSTIN: 27ABCDE1234F1Z5

    Notice: Our bank details have changed. Please transfer to new ICICI Bank A/C: 9988776655, IFSC: ICIC0001234.
    Urgent: Immediate settlement required within 24 hours.

    Taxable Value: 10,000.00
    Total Tax: 1,800.00
    Grand Total: 15,000.00  # Deliberate arithmetic mismatch (10000+1800 != 15000)
    """
    pdf_file = create_sample_pdf(text)

    try:
        res = analyze_pdf_invoice(pdf_file)
        assert res["success"] is True
        assert res["risk_score"] >= 70
        assert res["risk_level"] in ("High Risk", "Very High Risk")

        fields = res["extracted_fields"]
        assert fields["invoice_number"] == "INV-2026-9921"
        assert "27ABCDE1234F1Z5" in fields["gstins"]
        assert fields["arithmetic_consistent"] is False

        # Confirm evidence flags
        ev_types = [e["evidence_type"] for e in res["evidence"]]
        assert "bank_details_change" in ev_types
        assert "arithmetic_mismatch" in ev_types
    finally:
        if pdf_file.exists():
            os.remove(pdf_file)


def test_invoice_with_comparison_mismatch():
    original_text = """
    Invoice: INV-1001
    GSTIN: 29ABCDE5555G1Z9
    Bank A/C: 1122334455
    IFSC: HDFC0000012
    Subtotal: 5000.00
    Tax: 900.00
    Total: 5900.00
    """
    tampered_text = """
    Invoice: INV-1002
    GSTIN: 29ABCDE5555G1Z9
    Bank A/C: 9999888877  # Altered bank account!
    IFSC: HDFC0000012
    Subtotal: 5000.00
    Tax: 900.00
    Total: 5900.00
    """
    orig_pdf = create_sample_pdf(original_text)
    tamp_pdf = create_sample_pdf(tampered_text)

    try:
        res = analyze_pdf_invoice(tamp_pdf, comparison_pdf_path=orig_pdf)
        assert res["success"] is True
        assert res["comparison_report"] is not None
        assert res["comparison_report"]["bank_account_match"] is False
        assert any("mismatch" in e["evidence_type"] for e in res["evidence"])
    finally:
        if orig_pdf.exists():
            os.remove(orig_pdf)
        if tamp_pdf.exists():
            os.remove(tamp_pdf)
