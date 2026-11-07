import ipaddress
import re
from urllib.parse import urlparse

# Basic email regex
EMAIL_REGEX = re.compile(
    r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
)

# Forbidden schemes for URL scanning
ALLOWED_SCHEMES = {"http", "https"}


def validate_email_address(email: str) -> bool:
    """Validate email string structure."""
    if not email or len(email) > 120:
        return False
    return bool(EMAIL_REGEX.match(email.strip()))


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validate password length and character complexity."""
    if not password:
        return False, "Password cannot be empty."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit."
    return True, ""


def validate_url_input(url_str: str) -> tuple[bool, str]:
    """Validate URL syntax and safety."""
    if not url_str or not url_str.strip():
        return False, "URL cannot be empty."

    url = url_str.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL structure."

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False, f"Unsupported URL scheme: {parsed.scheme}. Only HTTP/HTTPS permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid or missing hostname in URL."

    if len(url) > 2048:
        return False, "URL exceeds maximum permitted length of 2048 characters."

    return True, url


def is_ssrf_safe_hostname(hostname: str) -> bool:
    """Check that hostname is not an internal, private, loopback or cloud metadata address."""
    if not hostname:
        return False

    host_lower = hostname.lower().strip()
    if host_lower in {"localhost", "loopback", "127.0.0.1", "::1"}:
        return False

    # Block AWS / GCP / Azure metadata endpoint
    if host_lower in {"169.254.169.254", "metadata.google.internal"}:
        return False

    # Try resolving to IP if it's an IP literal
    try:
        ip = ipaddress.ip_address(host_lower)
        if ip.is_loopback or ip.is_private or ip.is_reserved or ip.is_link_local:
            return False
    except ValueError:
        # Not a raw IP literal, it is a domain name
        pass

    return True
