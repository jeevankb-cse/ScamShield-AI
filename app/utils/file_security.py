import os
import uuid
from pathlib import Path
from werkzeug.utils import secure_filename

# Magic byte signatures for verified MIME types
MAGIC_SIGNATURES = {
    "jpg": [b"\xFF\xD8\xFF"],
    "jpeg": [b"\xFF\xD8\xFF"],
    "png": [b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"],
    "webp": [b"RIFF"],  # RIFF....WEBP
    "pdf": [b"%PDF-"],
}

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp", "pdf"}


def get_file_extension(filename: str) -> str:
    """Extract lowercased file extension without leading dot."""
    if not filename or "." not in filename:
        return ""
    return filename.rsplit(".", 1)[1].lower()


def validate_file_content(file_stream, ext: str) -> bool:
    """Inspect magic header bytes to verify real file format."""
    ext = ext.lower()
    if ext not in MAGIC_SIGNATURES:
        return False

    pos = file_stream.tell()
    file_stream.seek(0)
    header = file_stream.read(16)
    file_stream.seek(pos)

    if ext == "webp":
        return header.startswith(b"RIFF") and b"WEBP" in header[:16]

    for sig in MAGIC_SIGNATURES[ext]:
        if header.startswith(sig):
            return True
    return False


def validate_upload(file_obj, allowed_types: set = None) -> tuple[bool, str]:
    """Validate uploaded file for existence, allowed extension, and authentic header."""
    if not file_obj or file_obj.filename == "":
        return False, "No file was selected."

    ext = get_file_extension(file_obj.filename)
    allowed = allowed_types if allowed_types else ALLOWED_EXTENSIONS

    if ext not in allowed:
        return False, f"Unsupported file type (.{ext}). Allowed types: {', '.join(sorted(allowed))}"

    # Verify magic bytes
    if not validate_file_content(file_obj.stream, ext):
        return False, f"File content does not match reported .{ext} format."

    return True, ext


def save_securely(file_obj, upload_folder: Path, ext: str) -> Path:
    """Save upload using cryptographically random filename to prevent traversal and collision."""
    unique_name = f"{uuid.uuid4().hex}.{ext}"
    destination = Path(upload_folder) / unique_name
    file_obj.save(destination)
    return destination


def safe_delete(file_path: Path) -> None:
    """Delete temporary file safely after processing."""
    try:
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
    except Exception:
        pass
