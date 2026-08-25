"""
HorusShield Anomaly Detector — Feature 7
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Using Isolation Forest for detecting abnormal network behavior.
"""

import os
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from database.db_manager import db
from utils.logger import get_logger
from config import active_config as config

logger = get_logger("anomaly_detector", "ai")

class AnomalyDetector:
    """AI engine for detecting abnormal network behavior.
    
    Uses scikit-learn's Isolation Forest to identify outliers in
    network traffic patterns.
    """
    
    def __init__(self, model_path=None):
        self.model_path = model_path or os.path.join(config.AI_MODEL_DIR, "anomaly_detector.joblib")
        self.model = None
        self.features = config.ANOMALY_FEATURES
        self._load_model()
        
    def _load_model(self):
        """Load the pre-trained model from disk."""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                logger.info(f"Anomaly detector model loaded from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load anomaly detector model: {e}")
                self.model = None
        else:
            logger.warning("No anomaly detector model found. Needs training.")

    def detect(self, feature_vector):
        """Detect if the current traffic pattern is an anomaly.
        
        Args:
            feature_vector (dict): A dictionary of network features.
            
        Returns:
            dict: {is_anomaly: bool, score: float, confidence: float}
        """
        if self.model is None:
            return {"is_anomaly": False, "score": 0.0, "confidence": 0.0}
        
        # Validate input features
        if not isinstance(feature_vector, dict):
            logger.warning(f"Invalid feature_vector type: {type(feature_vector)}")
            return {"is_anomaly": False, "score": 0.0, "confidence": 0.0}
        
        for required_feature in self.features:
            if required_feature not in feature_vector:
                logger.warning(f"Missing required feature: {required_feature}")
                return {"is_anomaly": False, "score": 0.0, "confidence": 0.0}
            
        try:
            # Prepare data
            df = pd.DataFrame([feature_vector])
            # Ensure all features are present
            for f in self.features:
                if f not in df.columns:
                    df[f] = 0.0
            
            # Reorder columns to match training
            df = df[self.features]
            
            # Predict
            # IsolationForest returns -1 for outliers and 1 for inliers.
            prediction = self.model.predict(df)[0]
            scores = self.model.decision_function(df)[0] # Normalized outlier score
            
            is_anomaly = prediction == -1
            
            # Confidence calculation (heuristic)
            confidence = min(1.0, abs(scores) * 2) 
            
            if is_anomaly:
                logger.warning(f"Anomaly detected! Score: {scores:.4f}, Confidence: {confidence:.2%}")
                self._record_anomaly(feature_vector, scores, confidence)
                
            return {
                "is_anomaly": is_anomaly,
                "score": float(scores),
                "confidence": float(confidence)
            }
            
        except Exception as e:
            logger.error(f"Detection error: {e}")
            return {"is_anomaly": False, "score": 0.0, "confidence": 0.0}

    def _record_anomaly(self, features, score, confidence):
        """Record the anomaly in the database and create an alert."""
        attack_id = db.add_attack(
            attack_type="anomaly",
            severity="medium",
            confidence=confidence,
            details={
                "anomaly_score": score,
                "features": features
            },
            detected_by="ai"
        )
        
        db.add_alert(
            alert_type="anomaly",
            title="🧠 AI: Abnormal Behavior Detected",
            message=f"AI engine detected unusual network patterns (Score: {score:.2f}). Investigation recommended.",
            severity="medium",
            source="anomaly_detector",
            attack_id=attack_id,
            metadata={"anomaly_score": score, "confidence": confidence}
        )
        
        db.add_log("ai", f"Abnormal behavior detected (score: {score:.2f})", level="warning", source="anomaly_detector")

    def train(self, training_data):
        """Train the Isolation Forest model.

        This is UNSUPERVISED anomaly detection trained on normal-only
        traffic — there is no ground-truth "this was actually an attack"
        label in this data, so accuracy/precision/recall/F1 cannot be
        honestly computed here (they would require a labeled validation
        set of confirmed anomalies vs. confirmed normal traffic, which
        does not exist in HorusShield's training pipeline). What CAN be
        reported without fabrication: the configured contamination rate,
        and the fraction of training data the fitted model itself flags
        as anomalous (a self-consistency check, not a held-out metric).

        Args:
            training_data (list of dict): Historical feature vectors for 'normal' traffic.
        """
        empty_metrics = {
            "success": False, "training_samples": 0,
            "contamination_rate": None, "self_flagged_anomaly_rate": None,
            "metrics_note": "",
        }
        if not training_data:
            logger.warning("No training data provided for anomaly detector.")
            return {**empty_metrics, "metrics_note": "no training data provided"}

        try:
            logger.info(f"Training anomaly detector on {len(training_data)} samples...")
            df = pd.DataFrame(training_data)

            # Ensure all features are present
            for f in self.features:
                if f not in df.columns:
                    df[f] = 0.0

            X = df[self.features]

            # Isolation Forest
            model = IsolationForest(
                contamination=config.ANOMALY_CONTAMINATION,
                random_state=42,
                n_jobs=-1
            )
            model.fit(X)

            # Self-consistency check only — NOT a substitute for a real
            # precision/recall evaluation against labeled anomalies.
            self_predictions = model.predict(X)
            self_flagged_rate = float((self_predictions == -1).sum()) / len(self_predictions)

            # Save model
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump(model, self.model_path)
            self.model = model
            logger.info(f"Anomaly detector model trained and saved to {self.model_path}")
            return {
                "success": True,
                "training_samples": len(training_data),
                "contamination_rate": config.ANOMALY_CONTAMINATION,
                "self_flagged_anomaly_rate": round(self_flagged_rate, 4),
                "metrics_note": (
                    "accuracy/precision/recall/F1 are not reported — this is unsupervised "
                    "anomaly detection trained on normal-only data with no labeled ground "
                    "truth of confirmed anomalies to evaluate against. "
                    "self_flagged_anomaly_rate is a training-set self-consistency check "
                    "(what fraction of its own training data the fitted model flags as "
                    "anomalous), not a held-out accuracy metric."
                ),
            }

        except Exception as e:
            logger.error(f"Training error: {e}")
            return {**empty_metrics, "metrics_note": f"training error: {e}"}
