import os
import tempfile
from pathlib import Path
from PIL import Image, ImageDraw

from app.services.image_analyzer import analyze_image_file, preprocess_image_for_ocr
from app.utils.file_security import validate_file_content, validate_upload


def create_test_image(text: str) -> Path:
    """Generate a valid PNG image file with drawn text."""
    temp_dir = Path(tempfile.mkdtemp())
    img_path = temp_dir / "test_screenshot.png"

    img = Image.new("RGB", (400, 150), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, 40), text, fill=(0, 0, 0))
    img.save(str(img_path))
    return img_path


def test_image_preprocessing():
    img_path = create_test_image("Verify your KYC immediately")
    try:
        thresh = preprocess_image_for_ocr(img_path)
        assert thresh is not None
        assert thresh.shape[0] == 150
        assert thresh.shape[1] == 400
    finally:
        if img_path.exists():
            os.remove(img_path)


def test_image_analyzer_execution():
    img_path = create_test_image("Attention: SBI PAN KYC required")
    try:
        # Calls image analyzer: handles whether Tesseract is present or absent gracefully
        res = analyze_image_file(img_path)
        assert isinstance(res, dict)
        if res["success"]:
            assert "risk_score" in res
            assert "predicted_category" in res
        else:
            # If tesseract executable is not installed on the system, verifies descriptive warning
            assert "Tesseract" in res["error"] or "legible text" in res["error"]
    finally:
        if img_path.exists():
            os.remove(img_path)
