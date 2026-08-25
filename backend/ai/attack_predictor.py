"""
HorusShield Attack Predictor — Feature 8
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Time-series forecasting to predict attacks before they happen.
Using sliding window with scikit-learn (MLPRegressor for speed/simplicity).
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.neural_network import MLPRegressor

from database.db_manager import db
from utils.logger import get_logger
from config import active_config as config

logger = get_logger("attack_predictor", "ai")

class AttackPredictor:
    """AI engine for predicting network metrics and attacks.
    
    Uses historical traffic data to forecast future trends and
    warn of potential breaches.
    """
    
    def __init__(self, model_path=None):
        self.model_path = model_path or os.path.join(config.AI_MODEL_DIR, "attack_predictor.joblib")
        self.model = None
        self.features = config.ANOMALY_FEATURES
        self.window_size = 12 # E.g., last 60s if metrics are every 5s
        self._load_model()
        
    def _load_model(self):
        """Load the pre-trained model from disk."""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                logger.info(f"Attack predictor model loaded from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load attack predictor model: {e}")
                self.model = None
        else:
            logger.warning("No attack predictor model found. Needs training.")

    def predict(self, history):
        """Predict the next network state based on history.
        
        Args:
            history (list of dict): Chronological list of metric snapshots.
            
        Returns:
            dict: {prediction: dict, risk_level: float, warning: str}
        """
        if self.model is None or len(history) < self.window_size:
            return None
            
        try:
            # Flatten window into a single feature vector
            df = pd.DataFrame(history[-self.window_size:])
            df = df[self.features].fillna(0.0)
            X = df.values.flatten().reshape(1, -1)
            
            # Forecast next state
            forecast_values = self.model.predict(X)[0]
            forecast = dict(zip(self.features, forecast_values))
            
            # Evaluate risk of forecast
            risk_level, warning = self._evaluate_forecast_risk(forecast)
            
            if risk_level > 0.7:
                logger.warning(f"Predictive warning: {warning} (Risk: {risk_level:.2f})")
                self._record_prediction(forecast, risk_level, warning)
                
            return {
                "predicted_metrics": forecast,
                "risk_level": float(risk_level),
                "warning": warning
            }
            
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return None

    def _evaluate_forecast_risk(self, forecast):
        """Estimate the risk of the forecasted state."""
        # Simple threshold-based heuristic for predictive warnings
        risk = 0.0
        warnings = []
        
        if forecast.get('packets_per_sec', 0) > config.DDOS_PACKET_THRESHOLD * 0.8:
            risk += 0.4
            warnings.append("High traffic volume surge predicted")
            
        if forecast.get('syn_ratio', 0) > 0.3:
            risk += 0.3
            warnings.append("Potential SYN flood developing")
            
        if forecast.get('unique_dst_ports', 0) > config.PORTSCAN_PORT_THRESHOLD * 0.7:
            risk += 0.3
            warnings.append("Broad port probing activity predicted")

        risk = min(1.0, risk)
        warning_str = "; ".join(warnings) if warnings else "Normal conditions predicted"
        
        return risk, warning_str

    def _record_prediction(self, forecast, risk, warning):
        """Store the prediction in the database."""
        db.add_prediction(
            prediction_type="attack_likelihood",
            probability=risk,
            predicted_attack=warning,
            time_horizon=config.PREDICTION_HORIZON,
            features_used=forecast,
            model_version="v1.0"
        )
        
        db.add_alert(
            alert_type="prediction",
            title="🔮 Horus Forecast: Imminent Threat",
            message=f"HorusShield AI predicts a high risk ({risk:.0%}) of an attack in the next {config.PREDICTION_HORIZON} seconds: {warning}",
            severity="high" if risk > 0.8 else "medium",
            source="attack_predictor",
            metadata={"forecast": forecast, "risk": risk}
        )

    def train(self, data):
        """Train the MLPRegressor on historical sliding windows and compute
        real regression metrics via a held-out split.

        This is a REGRESSION model (forecasting continuous traffic metrics),
        not a classifier — accuracy/precision/recall/F1/confusion-matrix are
        not meaningful here by construction, not because they weren't
        computed. Returns MSE/MAE/R² instead, which are the metrics that
        actually apply to a regression task.
        """
        empty_metrics = {
            "success": False, "training_samples": 0, "test_samples": 0,
            "mse": None, "mae": None, "r2": None,
            "metrics_note": "",
        }
        if len(data) < self.window_size + 1:
            logger.info("Insufficient data for training attack predictor.")
            return {**empty_metrics, "metrics_note": f"need > {self.window_size} samples, got {len(data)}"}

        try:
            logger.info(f"Training attack predictor on {len(data)} samples...")
            df = pd.DataFrame(data)
            df = df[self.features].fillna(0.0)

            X = []
            y = []

            # Create sliding window dataset
            for i in range(len(df) - self.window_size):
                window = df.iloc[i:i+self.window_size].values.flatten()
                target = df.iloc[i+self.window_size].values
                X.append(window)
                y.append(target)

            X = np.array(X)
            y = np.array(y)

            metrics_note = "classification metrics (accuracy/precision/recall/F1) are not applicable — this is a regression model"
            X_test, y_test = None, None
            if len(X) >= 20:
                from sklearn.model_selection import train_test_split
                X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            else:
                X_train, y_train = X, y
                metrics_note += f"; also too few windowed samples ({len(X)}) for a held-out test split — trained on all of them, no test-set MSE/MAE/R² reported"

            # Lightweight MLP
            model = MLPRegressor(
                hidden_layer_sizes=(64, 32),
                max_iter=1000,
                random_state=42
            )
            model.fit(X_train, y_train)

            metrics = {
                "training_samples": len(X_train), "test_samples": 0,
                "mse": None, "mae": None, "r2": None, "metrics_note": metrics_note,
            }
            if X_test is not None:
                from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
                y_pred = model.predict(X_test)
                metrics.update({
                    "test_samples": len(X_test),
                    "mse": round(float(mean_squared_error(y_test, y_pred)), 4),
                    "mae": round(float(mean_absolute_error(y_test, y_pred)), 4),
                    "r2": round(float(r2_score(y_test, y_pred)), 4),
                })

            # Save
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump(model, self.model_path)
            self.model = model

            logger.info(f"Attack predictor model trained and saved to {self.model_path}")
            return {"success": True, **metrics}

        except Exception as e:
            logger.error(f"Training error: {e}")
            return {**empty_metrics, "metrics_note": f"training error: {e}"}
