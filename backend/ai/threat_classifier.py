"""
HorusShield Threat Classifier — Feature 9
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Using Random Forest for classifying detected attacks.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from utils.logger import get_logger
from config import active_config as config

logger = get_logger("threat_classifier", "ai")

class ThreatClassifier:
    """AI engine for classifying the type of cybersecurity threat.
    
    Categories: DDoS, Port Scan, Brute Force, Malware, Data Exfiltration, Normal.
    """
    
    CLASSES = ["Normal", "DDoS", "Port Scan", "Brute Force", "Malware", "Data Exfiltration"]
    
    def __init__(self, model_path=None):
        self.model_path = model_path or os.path.join(config.AI_MODEL_DIR, "threat_classifier.joblib")
        self.model = None
        self.features = config.ANOMALY_FEATURES
        self._load_model()
        
    def _load_model(self):
        """Load the pre-trained model from disk."""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                logger.info(f"Threat classifier model loaded from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load threat classifier model: {e}")
                self.model = None
        else:
            logger.warning("No threat classifier model found. Needs training.")

    def classify(self, feature_vector):
        """Classify the current network state into a threat category.
        
        Returns:
            dict: {class: str, probability: float, severity: str}
        """
        if self.model is None:
            return {"class": "Normal", "probability": 1.0, "severity": "info"}
            
        try:
            df = pd.DataFrame([feature_vector])
            # Ensure all features are present
            for f in self.features:
                if f not in df.columns:
                    df[f] = 0.0
            
            df = df[self.features]
            
            # Predict
            probs = self.model.predict_proba(df)[0]
            max_idx = np.argmax(probs)
            threat_class = self.CLASSES[max_idx]
            probability = probs[max_idx]
            
            severity = self._map_class_to_severity(threat_class, probability)
            
            return {
                "class": threat_class,
                "probability": float(probability),
                "severity": severity
            }
            
        except Exception as e:
            logger.error(f"Classification error: {e}")
            return {"class": "Normal", "probability": 1.0, "severity": "info"}

    def _map_class_to_severity(self, threat_class, probability):
        """Maps threat class and its certainty to a severity level."""
        if threat_class == "Normal":
            return "info"
        if threat_class in ["DDoS", "Data Exfiltration"]:
            return "critical" if probability > 0.8 else "high"
        if threat_class in ["Brute Force", "Malware"]:
            return "high" if probability > 0.7 else "medium"
        return "medium"

    def train(self, training_data, labels):
        """Train the Random Forest classifier and compute real evaluation
        metrics via a held-out test split — never report a metric that
        wasn't actually measured.

        Returns a dict: {success, training_samples, test_samples, accuracy,
        precision, recall, f1, confusion_matrix, classes, metrics_note}.
        `metrics_note` explains any metric that's None (e.g. too few
        samples for a meaningful split) instead of silently omitting it.
        """
        empty_metrics = {
            "success": False, "training_samples": 0, "test_samples": 0,
            "accuracy": None, "precision": None, "recall": None, "f1": None,
            "confusion_matrix": None, "classes": [], "metrics_note": "",
        }
        if len(training_data) == 0:
            logger.warning("No training data provided for threat classifier.")
            return {**empty_metrics, "metrics_note": "no training data provided"}

        if len(training_data) != len(labels):
            logger.error(f"Training data size ({len(training_data)}) doesn't match labels size ({len(labels)})")
            return {**empty_metrics, "metrics_note": "training data / label count mismatch"}

        try:
            logger.info(f"Training threat classifier on {len(training_data)} samples...")

            # Validate training data
            df = pd.DataFrame(training_data)
            for f in self.features:
                if f not in df.columns:
                    logger.warning(f"Missing feature in training data: {f}")
                    df[f] = 0.0

            X = df[self.features].fillna(0.0)
            y = np.array(labels)

            # Validate all labels are in CLASSES
            for label in set(labels):
                if label not in self.CLASSES:
                    logger.warning(f"Unknown label not in CLASSES: {label}")

            present_classes = sorted(set(labels))
            metrics_note = ""
            X_test, y_test, y_pred = None, None, None

            # A held-out test split needs enough samples per class to be
            # meaningful — with too few, sklearn's stratified split fails
            # outright, and even an unstratified split would be nearly
            # meaningless. Below that threshold, train on everything and
            # report honestly that no held-out evaluation was possible,
            # rather than faking a split or reporting train-set metrics
            # mislabeled as test metrics.
            min_per_class = min(list(labels).count(c) for c in present_classes)
            can_split = len(training_data) >= 20 and min_per_class >= 2 and len(present_classes) >= 2

            if can_split:
                from sklearn.model_selection import train_test_split

                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=0.25, random_state=42, stratify=y
                )
            else:
                X_train, y_train = X, y
                metrics_note = (
                    f"Training set too small/imbalanced for a held-out test split "
                    f"({len(training_data)} samples, {len(present_classes)} classes, "
                    f"min {min_per_class} per class) — model trained on all available "
                    f"data; no test-set accuracy/precision/recall/F1 is reported "
                    f"because none was actually measured."
                )

            model = RandomForestClassifier(n_estimators=100, random_state=42)
            model.fit(X_train, y_train)

            metrics = {
                "training_samples": len(X_train), "test_samples": 0,
                "accuracy": None, "precision": None, "recall": None, "f1": None,
                "confusion_matrix": None, "classes": present_classes,
                "metrics_note": metrics_note,
            }
            if X_test is not None:
                from sklearn.metrics import (
                    accuracy_score, precision_recall_fscore_support, confusion_matrix,
                )
                y_pred = model.predict(X_test)
                precision, recall, f1, _ = precision_recall_fscore_support(
                    y_test, y_pred, average="weighted", zero_division=0
                )
                cm = confusion_matrix(y_test, y_pred, labels=present_classes)
                metrics.update({
                    "test_samples": len(X_test),
                    "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
                    "precision": round(float(precision), 4),
                    "recall": round(float(recall), 4),
                    "f1": round(float(f1), 4),
                    "confusion_matrix": cm.tolist(),
                })

            # Save
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump(model, self.model_path)
            self.model = model
            logger.info(f"Threat classifier model trained and saved to {self.model_path}")

            return {"success": True, **metrics}

        except Exception as e:
            logger.error(f"Training error: {e}")
            return {**empty_metrics, "metrics_note": f"training error: {e}"}
