import os
import joblib
import pandas as pd
from typing import Dict, Any
from threatscope.ml.feature_extractor import extract_features_from_url, FEATURE_NAMES

MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "threatscope_rf_model.joblib")

class ThreatScopeClassifier:
    def __init__(self, model_path: str = MODEL_PATH):
        self.model_path = model_path
        self.model = None
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
            except Exception:
                self.model = None

    def predict(self, url: str) -> Dict[str, Any]:
        features = extract_features_from_url(url)
        df_feat = pd.DataFrame([features])[FEATURE_NAMES]

        if self.model is not None:
            proba = float(self.model.predict_proba(df_feat)[0][1])
            is_malicious = proba >= 0.50
        else:
            # Deterministic heuristic fallback
            score = 0.0
            if features["has_ip_in_host"]: score += 0.40
            if features["is_suspicious_tld"]: score += 0.25
            if features["has_at_symbol"]: score += 0.30
            if features["has_exe_or_zip"]: score += 0.35
            if features["url_entropy"] > 4.5: score += 0.20
            if any(features.get(f"kw_{k}", 0) for k in ["login", "verify", "secure"]): score += 0.25
            proba = min(round(score, 4), 0.99)
            is_malicious = proba >= 0.50

        return {
            "url": url,
            "malicious_probability": round(proba, 4),
            "is_malicious_prediction": is_malicious,
            "feature_count": len(features),
            "top_features": {
                "entropy": features["url_entropy"],
                "has_ip": bool(features["has_ip_in_host"]),
                "suspicious_tld": bool(features["is_suspicious_tld"]),
                "length": features["url_length"]
            }
        }
