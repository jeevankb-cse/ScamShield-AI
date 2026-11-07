import logging
from pathlib import Path
import joblib

logger = logging.getLogger(__name__)


class ModelRegistry:
    """Manages lazy-loading and caching of trained ML models and vectorizers."""

    _instance = None

    def __init__(self, artifacts_dir: Path = None):
        if artifacts_dir is None:
            self.artifacts_dir = Path(__file__).resolve().parent.parent.parent / "ml" / "artifacts"
        else:
            self.artifacts_dir = Path(artifacts_dir)

        self._text_model = None
        self._text_vectorizer = None
        self._url_model = None
        self._url_features = None
        self._email_model = None
        self._email_vectorizer = None

    @classmethod
    def get_instance(cls, artifacts_dir: Path = None):
        if cls._instance is None:
            cls._instance = ModelRegistry(artifacts_dir)
        return cls._instance

    @property
    def text_model(self):
        if self._text_model is None:
            p = self.artifacts_dir / "text_classifier.joblib"
            if p.exists():
                try:
                    self._text_model = joblib.load(p)
                except Exception as e:
                    logger.error(f"Failed to load text classifier: {e}")
        return self._text_model

    @property
    def text_vectorizer(self):
        if self._text_vectorizer is None:
            p = self.artifacts_dir / "text_vectorizer.joblib"
            if p.exists():
                try:
                    self._text_vectorizer = joblib.load(p)
                except Exception as e:
                    logger.error(f"Failed to load text vectorizer: {e}")
        return self._text_vectorizer

    @property
    def url_model(self):
        if self._url_model is None:
            p = self.artifacts_dir / "url_classifier.joblib"
            if p.exists():
                try:
                    self._url_model = joblib.load(p)
                except Exception as e:
                    logger.error(f"Failed to load url classifier: {e}")
        return self._url_model

    @property
    def email_model(self):
        if self._email_model is None:
            p = self.artifacts_dir / "email_classifier.joblib"
            if p.exists():
                try:
                    self._email_model = joblib.load(p)
                except Exception as e:
                    logger.error(f"Failed to load email classifier: {e}")
        return self._email_model

    @property
    def email_vectorizer(self):
        if self._email_vectorizer is None:
            p = self.artifacts_dir / "email_vectorizer.joblib"
            if p.exists():
                try:
                    self._email_vectorizer = joblib.load(p)
                except Exception as e:
                    logger.error(f"Failed to load email vectorizer: {e}")
        return self._email_vectorizer


# Global singleton access
model_registry = ModelRegistry.get_instance()
