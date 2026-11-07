import logging
from pathlib import Path
from typing import Dict, Any, List
import pymupdf  # fitz

logger = logging.getLogger(__name__)


def extract_pdf_content(pdf_path: Path) -> Dict[str, Any]:
    """Extract text, page count, and metadata from PDF using PyMuPDF."""
    try:
        doc = pymupdf.open(str(pdf_path))
        num_pages = len(doc)

        full_text = []
        page_texts = []

        for page_idx in range(num_pages):
            page = doc[page_idx]
            text = page.get_text("text")
            page_texts.append(text)
            full_text.append(text)

        metadata = doc.metadata or {}
        doc.close()

        combined_text = "\n\n".join(full_text)

        return {
            "success": True,
            "page_count": num_pages,
            "full_text": combined_text,
            "page_texts": page_texts,
            "metadata": metadata,
            "error": None
        }
    except Exception as e:
        logger.error(f"Failed to read PDF with PyMuPDF: {e}")
        return {
            "success": False,
            "page_count": 0,
            "full_text": "",
            "page_texts": [],
            "metadata": {},
            "error": f"Failed to parse PDF document: {str(e)}"
        }
