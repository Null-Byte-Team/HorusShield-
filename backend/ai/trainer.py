"""
HorusShield AI Trainer
━━━━━━━━━━━━━━━━━━━━━━━
Automated training and maintenance of AI models.
"""

import json
import threading
import time
import random
from datetime import datetime

from ai.anomaly_detector import AnomalyDetector
from ai.attack_predictor import AttackPredictor
from ai.threat_classifier import ThreatClassifier
from database.db_manager import db
from utils.logger import get_logger
from config import active_config as config

logger = get_logger("ai_trainer", "ai")

class AITrainer:
    """Manages the training cycle for all HorusShield AI models.
    
    Can perform:
    - Baseline training on normal historical data.
    - Automated periodic retraining.
    - Synthetic data generation for initial cold-start.
    """
    
    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.attack_predictor = AttackPredictor()
        self.threat_classifier = ThreatClassifier()
        self._running = False
        self._thread = None
        # Progress state exposed via GET /api/ai/train/status — updated as
        # training proceeds rather than only reporting "running"/"idle".
        self._progress = {"stage": "idle", "percent": 0, "model": None, "started_at": None}

    def get_progress(self):
        return dict(self._progress)

    def _set_progress(self, stage, percent, model=None):
        self._progress.update({"stage": stage, "percent": percent, "model": model})
        logger.info(f"Training progress: {stage} ({percent}%){' - ' + model if model else ''}")

    def _record_metadata(self, model_name, metrics, training_source):
        """Persist one training run's metadata/metrics — model_version is a
        UTC timestamp, unique per run, so history is queryable via
        db.get_model_metadata(model_name)."""
        if not isinstance(metrics, dict):
            # Older-style bool return from a model that wasn't updated —
            # shouldn't happen post-Phase-9, but don't crash if it does.
            metrics = {"success": bool(metrics), "metrics_note": "legacy bool return, no metrics available"}
        version = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        cm = metrics.get("confusion_matrix")
        try:
            db.add_model_metadata(
                model_name=model_name,
                model_version=version,
                training_source=training_source,
                training_samples=metrics.get("training_samples", 0),
                test_samples=metrics.get("test_samples", 0),
                accuracy=metrics.get("accuracy"),
                precision_score=metrics.get("precision"),
                recall_score=metrics.get("recall"),
                f1_score=metrics.get("f1"),
                roc_auc=metrics.get("roc_auc"),
                confusion_matrix=json.dumps(cm) if cm is not None else "",
                mse=metrics.get("mse"),
                mae=metrics.get("mae"),
                r2_score=metrics.get("r2"),
                metrics_note=metrics.get("metrics_note", ""),
                success=1 if metrics.get("success") else 0,
            )
        except Exception as e:
            logger.error(f"Failed to record model metadata for {model_name}: {e}")
        return metrics.get("success", False)

    def start(self):
        """Starts the periodic retraining thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._training_loop, daemon=True)
        self._thread.start()
        logger.info("AI Trainer background thread started.")

    def stop(self):
        self._running = False

    def _training_loop(self):
        """Wait for interval then retrain."""
        while self._running:
            # Cold start check: if no models exist, train on synthetic data
            if self.anomaly_detector.model is None:
                logger.info("Cold start: Generating synthetic data for initial models...")
                self.train_on_synthetic_data()
            
            time.sleep(config.RETRAIN_INTERVAL)
            if not self._running: break
            
            logger.info("Triggering periodic model retraining...")
            self.train_on_history()

    def train_on_history(self):
        """Extract data from database and train models."""
        self._progress = {"stage": "starting", "percent": 0, "model": None,
                           "started_at": datetime.utcnow().isoformat()}
        try:
            # 1. Get history from network_traffic table
            self._set_progress("loading historical data", 5)
            history = db.get_traffic_history(minutes=60*24) # Last 24 hours
            if len(history) < 100:
                logger.info("Insufficient real data for quality training. Skipping.")
                self._set_progress("idle", 0)
                return False
            
            # 2. Train Anomaly Detector (Normal baseline)
            self._set_progress("training", 20, "anomaly_detector")
            normal_data = self._filter_normal_traffic(history)
            metrics = self.anomaly_detector.train(normal_data)
            self._record_metadata("anomaly_detector", metrics, "history")
            
            # 3. Train Attack Predictor
            self._set_progress("training", 50, "attack_predictor")
            metrics = self.attack_predictor.train(history)
            self._record_metadata("attack_predictor", metrics, "history")
            
            # 4. Train Threat Classifier
            self._set_progress("training", 75, "threat_classifier")
            labeled_data = self._build_labeled_dataset(history)
            classifier_ok = True
            if labeled_data:
                features_list, labels_list = labeled_data
                if features_list and labels_list:
                    metrics = self.threat_classifier.train(features_list, labels_list)
                    classifier_ok = self._record_metadata("threat_classifier", metrics, "history")
                    logger.info(f"Threat classifier trained on {len(features_list)} labeled samples.")
            
            self._set_progress("complete", 100)
            logger.info("Training on historical data complete.")
            return True
            
        except Exception as e:
            logger.error(f"History training error: {e}")
            self._set_progress("failed", 0)
            return False

    def _filter_normal_traffic(self, history):
        """Subsets history to only include periods with no active attacks."""
        if not history:
            return []
        
        filtered = []
        for traffic_entry in history:
            # Check if there were active attacks at this time
            timestamp = traffic_entry.get('timestamp')
            if timestamp:
                # Query database for attacks during this timestamp
                active_attacks = db.get_active_attacks_count()
                # If no attacks were active during this period, include in normal training set
                if active_attacks == 0:
                    filtered.append(traffic_entry)
            else:
                # No timestamp, include conservatively
                filtered.append(traffic_entry)
        
        return filtered if filtered else history  # Fallback to all if nothing filtered

    def _build_labeled_dataset(self, history):
        """Build labeled training data from attack history."""
        try:
            features = []
            labels = []
            
            # Get all attacks from the past 24 hours
            attacks = db.get_attacks(limit=1000)
            
            # Add attack samples
            for attack in attacks:
                attack_type = attack.get('attack_type', 'Normal')
                # Map attack types to classifier classes
                if attack_type == 'ddos':
                    label = 'DDoS'
                elif attack_type == 'port_scan':
                    label = 'Port Scan'
                elif attack_type == 'brute_force':
                    label = 'Brute Force'
                elif attack_type == 'malware':
                    label = 'Malware'
                elif attack_type == 'data_exfiltration':
                    label = 'Data Exfiltration'
                else:
                    label = 'Normal'
                
                # Extract features from attack details
                details = attack.get('details', {})
                if isinstance(details, str):
                    import json
                    details = json.loads(details) if details else {}
                
                feature_vector = {
                    'packets_per_sec': details.get('packets_per_sec', 0),
                    'bytes_per_sec': details.get('bytes_per_sec', 0),
                    'unique_src_ips': details.get('unique_src_ips', 1),
                    'unique_dst_ports': details.get('unique_dst_ports', 1),
                    'syn_ratio': details.get('syn_ratio', 0),
                    'udp_ratio': details.get('udp_ratio', 0),
                    'icmp_ratio': details.get('icmp_ratio', 0),
                    'avg_packet_size': details.get('avg_packet_size', 64),
                    'connection_count': details.get('connection_count', 0),
                    'entropy': details.get('entropy', 0)
                }
                features.append(feature_vector)
                labels.append(label)
            
            # Add normal samples from history
            normal_samples = self._filter_normal_traffic(history[:200])
            for sample in normal_samples[:100]:  # Limit normal samples
                feature_vector = {
                    'packets_per_sec': sample.get('packets_per_sec', 50),
                    'bytes_per_sec': sample.get('bytes_per_sec', 5000),
                    'unique_src_ips': sample.get('unique_src_ips', 5),
                    'unique_dst_ports': sample.get('unique_dst_ports', 20),
                    'syn_ratio': sample.get('syn_ratio', 0.05),
                    'udp_ratio': sample.get('udp_ratio', 0.2),
                    'icmp_ratio': sample.get('icmp_ratio', 0.01),
                    'avg_packet_size': sample.get('avg_packet_size', 500),
                    'connection_count': sample.get('connection_count', 50),
                    'entropy': sample.get('entropy', 3.0)
                }
                features.append(feature_vector)
                labels.append('Normal')
            
            return (features, labels) if features and labels else None
        except Exception as e:
            logger.error(f"Error building labeled dataset: {e}")
            return None

    def train_on_synthetic_data(self):
        """Bootstraps the AI engine with realistically simulated data.

        NOTE on metrics honesty: metrics computed here (accuracy, MSE, etc.)
        are measured against a held-out split of this SYNTHETIC data, not
        real network traffic — they demonstrate the training/evaluation
        pipeline works correctly, not real-world model performance. Every
        metadata row this produces is tagged training_source='synthetic' so
        this distinction is never lost when reading results back.
        """
        self._progress = {"stage": "starting", "percent": 0, "model": None,
                           "started_at": datetime.utcnow().isoformat()}
        logger.info("Generating synthetic training data...")

        # 1. Normal Traffic samples
        self._set_progress("generating synthetic data", 5)
        normal_samples = []
        for _ in range(500):
            sample = {
                "packets_per_sec": random.uniform(20, 150),
                "bytes_per_sec": random.uniform(1000, 15000),
                "unique_src_ips": random.randint(2, 10),
                "unique_dst_ports": random.randint(5, 50),
                "syn_ratio": random.uniform(0.01, 0.05),
                "udp_ratio": random.uniform(0.1, 0.3),
                "icmp_ratio": random.uniform(0.01, 0.02),
                "avg_packet_size": random.uniform(64, 1500),
                "connection_count": random.randint(10, 100),
                "entropy": random.uniform(2.0, 4.0)
            }
            normal_samples.append(sample)

        self._set_progress("training", 25, "anomaly_detector")
        metrics = self.anomaly_detector.train(normal_samples)
        self._record_metadata("anomaly_detector", metrics, "synthetic")

        self._set_progress("training", 50, "attack_predictor")
        metrics = self.attack_predictor.train(normal_samples)
        self._record_metadata("attack_predictor", metrics, "synthetic")

        # 2. Labeled Traffic for Classifier
        X = []
        y = []
        # Normal
        for s in normal_samples[:100]:
            X.append(s); y.append("Normal")
        # DDoS
        for _ in range(50):
            X.append({
                "packets_per_sec": random.uniform(2000, 5000),
                "bytes_per_sec": random.uniform(1000000, 5000000),
                "unique_src_ips": 1,
                "unique_dst_ports": random.randint(1, 5),
                "syn_ratio": random.uniform(0.7, 0.9),
                "udp_ratio": 0.05, "icmp_ratio": 0.01, "avg_packet_size": 64,
                "connection_count": 500, "entropy": 0.5
            })
            y.append("DDoS")
        # Port Scan
        for _ in range(50):
            X.append({
                "packets_per_sec": random.uniform(100, 300),
                "bytes_per_sec": random.uniform(10000, 50000),
                "unique_src_ips": 1,
                "unique_dst_ports": random.randint(1000, 2000),
                "syn_ratio": random.uniform(0.1, 0.3),
                "udp_ratio": 0.1, "icmp_ratio": 0.01, "avg_packet_size": 64,
                "connection_count": 200, "entropy": 5.0
            })
            y.append("Port Scan")

        self._set_progress("training", 80, "threat_classifier")
        metrics = self.threat_classifier.train(X, y)
        self._record_metadata("threat_classifier", metrics, "synthetic")

        self._set_progress("complete", 100)
        logger.info("Synthetic training complete. All models initialized.")
        return True
