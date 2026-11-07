import logging
import numpy as np
from typing import Dict, Any
from app.ml.model_loader import model_registry
from ml.training.train_url_model import extract_url_features, FEATURE_NAMES

logger = logging.getLogger(__name__)


def predict_url_phishing(url_str: str) -> Dict[str, Any]:
    """Extract features from target URL and score against trained classifier."""
    model = model_registry.url_model

    if model is None:
        return {
            "model_available": False,
            "raw_probability": 0.0,
            "predicted_label": 0,
            "features": {},
            "error": "URL phishing model not loaded."
        }

    feat_values = extract_url_features(url_str)
    feat_dict = dict(zip(FEATURE_NAMES, feat_values))

    feat_array = np.array([feat_values])
    try:
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(feat_array)[0]
            prob_phish = float(probs[1]) if len(probs) > 1 else 0.5
        else:
            prob_phish = 1.0 if model.predict(feat_array)[0] == 1 else 0.0
        predicted_label = int(model.predict(feat_array)[0])
    except Exception as e:
        logger.error(f"URL prediction error: {e}")
        prob_phish = 0.5
        predicted_label = 1

    return {
        "model_available": True,
        "raw_probability": prob_phish,
        "predicted_label": predicted_label,
        "features": feat_dict,
        "error": None
    }
