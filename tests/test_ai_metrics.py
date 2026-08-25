"""Tests for ai/trainer.py, ai/threat_classifier.py, ai/attack_predictor.py,
ai/anomaly_detector.py — real metric computation, not mocked."""

import random


def _make_classifier_data(n_per_class=15):
    """Enough samples per class to trigger a real train/test split."""
    X, y = [], []
    for _ in range(n_per_class):
        X.append(
            {
                "packets_per_sec": random.uniform(20, 150),
                "bytes_per_sec": random.uniform(1000, 15000),
                "unique_src_ips": random.randint(2, 10),
                "unique_dst_ports": random.randint(5, 50),
                "syn_ratio": random.uniform(0.01, 0.05),
                "udp_ratio": random.uniform(0.1, 0.3),
                "icmp_ratio": random.uniform(0.01, 0.02),
                "avg_packet_size": random.uniform(64, 1500),
                "connection_count": random.randint(10, 100),
                "entropy": random.uniform(2.0, 4.0),
            }
        )
        y.append("Normal")
    for _ in range(n_per_class):
        X.append(
            {
                "packets_per_sec": random.uniform(2000, 5000),
                "bytes_per_sec": random.uniform(1000000, 5000000),
                "unique_src_ips": 1,
                "unique_dst_ports": random.randint(1, 5),
                "syn_ratio": random.uniform(0.7, 0.9),
                "udp_ratio": 0.05,
                "icmp_ratio": 0.01,
                "avg_packet_size": 64,
                "connection_count": 500,
                "entropy": 0.5,
            }
        )
        y.append("DDoS")
    return X, y


def test_threat_classifier_computes_real_metrics_with_enough_data(tmp_path):
    from ai.threat_classifier import ThreatClassifier

    clf = ThreatClassifier(model_path=str(tmp_path / "test_clf.joblib"))
    X, y = _make_classifier_data(n_per_class=15)
    result = clf.train(X, y)

    assert result["success"] is True
    assert result["test_samples"] > 0  # real split happened
    assert 0.0 <= result["accuracy"] <= 1.0
    assert 0.0 <= result["precision"] <= 1.0
    assert 0.0 <= result["recall"] <= 1.0
    assert 0.0 <= result["f1"] <= 1.0
    assert result["confusion_matrix"] is not None
    assert len(result["confusion_matrix"]) == len(result["classes"])


def test_threat_classifier_reports_honestly_with_too_little_data(tmp_path):
    from ai.threat_classifier import ThreatClassifier

    clf = ThreatClassifier(model_path=str(tmp_path / "test_clf2.joblib"))
    X, y = _make_classifier_data(n_per_class=2)  # too few for a real split
    result = clf.train(X, y)

    assert result["success"] is True  # still trains successfully
    assert result["test_samples"] == 0  # but no held-out evaluation happened
    assert result["accuracy"] is None  # and it says so, not a fabricated number
    assert "too small" in result["metrics_note"].lower()


def test_threat_classifier_rejects_empty_data(tmp_path):
    from ai.threat_classifier import ThreatClassifier

    clf = ThreatClassifier(model_path=str(tmp_path / "test_clf3.joblib"))
    result = clf.train([], [])
    assert result["success"] is False
    assert result["metrics_note"]


def test_attack_predictor_reports_regression_metrics_not_classification(tmp_path):
    from ai.attack_predictor import AttackPredictor

    pred = AttackPredictor(model_path=str(tmp_path / "test_pred.joblib"))
    data = [
        {
            "packets_per_sec": random.uniform(20, 150),
            "bytes_per_sec": random.uniform(1000, 15000),
            "unique_src_ips": random.randint(2, 10),
            "unique_dst_ports": random.randint(5, 50),
            "syn_ratio": random.uniform(0.01, 0.05),
            "udp_ratio": random.uniform(0.1, 0.3),
            "icmp_ratio": random.uniform(0.01, 0.02),
            "avg_packet_size": random.uniform(64, 1500),
            "connection_count": random.randint(10, 100),
            "entropy": random.uniform(2.0, 4.0),
        }
        for _ in range(60)
    ]

    result = pred.train(data)
    assert result["success"] is True
    assert (
        "not applicable" in result["metrics_note"].lower()
        or "not applic" in result["metrics_note"].lower()
    )
    # A regressor never reports classification-only metrics as if they were computed
    assert "accuracy" not in result
    assert "precision" not in result


def test_anomaly_detector_never_fabricates_supervised_metrics(tmp_path):
    from ai.anomaly_detector import AnomalyDetector

    det = AnomalyDetector(model_path=str(tmp_path / "test_anom.joblib"))
    data = [
        {
            "packets_per_sec": random.uniform(20, 150),
            "bytes_per_sec": random.uniform(1000, 15000),
            "unique_src_ips": random.randint(2, 10),
            "unique_dst_ports": random.randint(5, 50),
            "syn_ratio": random.uniform(0.01, 0.05),
            "udp_ratio": random.uniform(0.1, 0.3),
            "icmp_ratio": random.uniform(0.01, 0.02),
            "avg_packet_size": random.uniform(64, 1500),
            "connection_count": random.randint(10, 100),
            "entropy": random.uniform(2.0, 4.0),
        }
        for _ in range(50)
    ]

    result = det.train(data)
    assert result["success"] is True
    assert "accuracy" not in result  # never fabricated for unsupervised training
    assert 0.0 <= result["self_flagged_anomaly_rate"] <= 1.0
    assert (
        "no labeled ground truth" in result["metrics_note"].lower()
        or "unsupervised" in result["metrics_note"].lower()
    )


def test_trainer_persists_metadata_for_every_model(db):
    from ai.trainer import AITrainer

    trainer = AITrainer()
    trainer.train_on_synthetic_data()

    for model_name in ("anomaly_detector", "attack_predictor", "threat_classifier"):
        rows = db.get_model_metadata(model_name=model_name, limit=1)
        assert len(rows) >= 1, f"no metadata recorded for {model_name}"
        assert rows[0]["training_source"] == "synthetic"
        assert rows[0]["model_version"]  # non-empty timestamp-based version


def test_trainer_reports_progress(db):
    from ai.trainer import AITrainer

    trainer = AITrainer()
    assert trainer.get_progress()["stage"] == "idle"
    trainer.train_on_synthetic_data()
    assert trainer.get_progress()["stage"] == "complete"
    assert trainer.get_progress()["percent"] == 100


def test_ai_train_metadata_endpoint(client, auth_headers, db):
    from ai.trainer import AITrainer

    trainer = AITrainer()
    trainer.train_on_synthetic_data()

    resp = client.get("/api/ai/train/metadata?model=threat_classifier", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["model_name"] == "threat_classifier"


def test_ai_train_metadata_rejects_unknown_model(client, auth_headers):
    resp = client.get("/api/ai/train/metadata?model=not_a_real_model", headers=auth_headers)
    assert resp.status_code == 400
