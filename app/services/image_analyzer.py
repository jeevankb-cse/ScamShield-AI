import os
import logging
from pathlib import Path
from typing import Dict, Any

from PIL import Image
import cv2
import numpy as np
import pytesseract
from flask import current_app, has_app_context

from app.services.text_analyzer import analyze_text_message

logger = logging.getLogger(__name__)
DEFAULT_TESSERACT_PATH = r"C:\Program Files\Tesseract-OCR\tesseract.exe"


def preprocess_image_for_ocr(image_path: Path) -> np.ndarray:
    """Preprocess image with OpenCV (grayscale, denoising, adaptive thresholding) to optimize OCR accuracy."""
    img = cv2.imread(str(image_path))
    if img is None:
        # Fallback to PIL loading
        pil_img = Image.open(str(image_path)).convert("RGB")
        img = np.array(pil_img)[:, :, ::-1]

    # Convert to grayscale
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # Denoise
    denoised = cv2.fastNlMeansDenoising(gray, h=10)

    # Adaptive thresholding for high contrast text
    thresh = cv2.adaptiveThreshold(
        denoised, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 2
    )

    return thresh


def extract_text_from_image(image_path: Path) -> tuple[bool, str, str]:
    """
    Extract text via Tesseract OCR.
    Returns: (success: bool, extracted_text: str, message: str)
    """
    # Configure pytesseract path from config or default fallback
    tesseract_cmd = DEFAULT_TESSERACT_PATH
    if has_app_context():
        tesseract_cmd = current_app.config.get("TESSERACT_CMD", DEFAULT_TESSERACT_PATH)

    if os.path.exists(tesseract_cmd):
        pytesseract.pytesseract.tesseract_cmd = tesseract_cmd

    try:
        # Preprocess with OpenCV
        processed_img = preprocess_image_for_ocr(image_path)
        text = pytesseract.image_to_string(processed_img, config="--psm 6")

        if not text.strip():
            # Retry with raw image if thresholding removed faint text
            raw_pil = Image.open(str(image_path))
            text = pytesseract.image_to_string(raw_pil)

        cleaned_text = text.strip()
        if not cleaned_text:
            return False, "", "No legible text could be extracted from the uploaded image."

        return True, cleaned_text, "Text extracted successfully."

    except pytesseract.TesseractNotFoundError:
        logger.warning("Tesseract binary not found on host machine.")
        # Attempt fallback to basic image metadata / mock check if user provided sample
        return False, "", "Tesseract OCR engine is not installed on this server. Please install Tesseract or check TESSERACT_CMD in .env."
    except Exception as e:
        logger.error(f"OCR extraction failed: {e}")
        return False, "", f"OCR extraction failed: {str(e)}"


def analyze_image_file(image_path: Path) -> Dict[str, Any]:
    """Extract text from screenshot and send to risk analysis engine."""
    ocr_ok, extracted_text, msg = extract_text_from_image(image_path)

    if not ocr_ok:
        return {
            "success": False,
            "error": msg,
            "extracted_text": "",
            "requires_tesseract": "Tesseract OCR engine is not installed" in msg
        }

    # Pass extracted text to comprehensive text scanner
    text_result = analyze_text_message(extracted_text)
    text_result["input_type"] = "image"
    text_result["extracted_text"] = extracted_text

    return text_result
