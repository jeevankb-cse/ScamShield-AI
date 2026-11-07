import re
import string
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

# Compiled regex patterns for extraction
URL_REGEX = re.compile(
    r'(?:https?:\/\/|www\.)[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}(?:\/[^\s"\'<>]*)?',
    re.IGNORECASE,
)
UPI_REGEX = re.compile(
    r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}',
    re.IGNORECASE,
)
PHONE_REGEX = re.compile(
    r'(?:\+91[\-\s]?)?[6-9]\d{9}\b'
)
OTP_REGEX = re.compile(
    r'\b(?:otp|one[- ]time[- ]password|pin|mpin|code|verification code)\s*(?:is|:)?\s*([0-9]{4,8})\b',
    re.IGNORECASE,
)
CURRENCY_REGEX = re.compile(
    r'(?:rs\.?|inr|₹)\s*([0-9,]+(?:\.[0-9]{1,2})?)',
    re.IGNORECASE,
)

# Standard English stopwords fallback
FALLBACK_STOPWORDS = {
    "i", "me", "my", "myself", "we", "our", "ours", "ourselves", "you", "your",
    "yours", "yourself", "yourselves", "he", "him", "his", "himself", "she",
    "her", "hers", "herself", "it", "its", "itself", "they", "them", "their",
    "theirs", "themselves", "what", "which", "who", "whom", "this", "that",
    "these", "those", "am", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "having", "do", "does", "did", "doing", "a", "an",
    "the", "and", "but", "if", "or", "because", "as", "until", "while", "of",
    "at", "by", "for", "with", "about", "against", "between", "into", "through",
    "during", "before", "after", "above", "below", "to", "from", "up", "down",
    "in", "out", "on", "off", "over", "under", "again", "further", "then",
    "once", "here", "there", "when", "where", "why", "how", "all", "any",
    "both", "each", "few", "more", "most", "other", "some", "such", "no", "nor",
    "not", "only", "own", "same", "so", "than", "too", "very", "s", "t", "can",
    "will", "just", "don", "should", "now"
}


def get_stopwords() -> set:
    """Retrieve NLTK stopwords or fallback set."""
    try:
        return set(stopwords.words("english"))
    except Exception:
        return FALLBACK_STOPWORDS


def extract_urls(text: str) -> list:
    """Extract embedded URLs from text."""
    if not text:
        return []
    return URL_REGEX.findall(text)


def extract_upi_ids(text: str) -> list:
    """Extract UPI VPA handles (e.g., name@okhdfcbank, help@upi)."""
    if not text:
        return []
    matches = UPI_REGEX.findall(text)
    # Filter out common email domains that are not UPI
    non_upi_domains = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com"}
    return [m for m in matches if m.split("@")[-1].lower() not in non_upi_domains]


def extract_phones(text: str) -> list:
    """Extract Indian telephone numbers."""
    if not text:
        return []
    return PHONE_REGEX.findall(text)


def extract_amounts(text: str) -> list:
    """Extract Indian currency amounts."""
    if not text:
        return []
    return CURRENCY_REGEX.findall(text)


def clean_text_for_nlp(text: str) -> str:
    """Clean text for TF-IDF vectorization and NLP classification."""
    if not text or not isinstance(text, str):
        return ""

    # Replace URLs with placeholder token
    cleaned = URL_REGEX.sub(" URL_TOKEN ", text)

    # Replace currency amounts with placeholder
    cleaned = CURRENCY_REGEX.sub(" CURRENCY_TOKEN ", cleaned)

    # Replace phone numbers
    cleaned = PHONE_REGEX.sub(" PHONE_TOKEN ", cleaned)

    # Replace UPI handles
    cleaned = UPI_REGEX.sub(" UPI_TOKEN ", cleaned)

    # Lowercase
    cleaned = cleaned.lower()

    # Remove special punctuation except alphanumeric and tokens
    cleaned = re.sub(r'[^a-z0-9_\s]', ' ', cleaned)

    # Tokenize and filter stopwords
    stop_words = get_stopwords()
    try:
        tokens = word_tokenize(cleaned)
    except Exception:
        tokens = cleaned.split()

    filtered_tokens = [t for t in tokens if len(t) > 1 and t not in stop_words]

    return " ".join(filtered_tokens)


def sanitize_for_preview(text: str, max_chars: int = 140) -> str:
    """Mask potential OTPs or credentials before logging or database preview."""
    if not text:
        return ""

    # Mask potential OTP numbers
    masked = OTP_REGEX.sub(r"OTP: [REDACTED]", text)

    # Truncate
    if len(masked) > max_chars:
        return masked[:max_chars].strip() + "..."
    return masked.strip()
