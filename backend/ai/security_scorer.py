"""
HorusShield Security Scorer — Improved
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Computes a weighted composite security score (0-100).

Improvements over v4-3:
  • open_ports is always a list (never a raw JSON string) thanks to
    db_manager._decode_json_fields — the isinstance guard is still kept
    as a safety net.
  • Score components are clamped to [0, 100] before weighting.
  • Trend is determined by comparing against the previous score (not
    just hard-coded "stable").
  • ai_confidence deducts correctly when AI is explicitly disabled.
  • Type annotations throughout.
"""

import json
from typing import Dict, Optional

from database.db_manager import db
from utils.logger import get_logger
from config import active_config as config

logger = get_logger("security_scorer", "ai")

# Ports that raise the vulnerability exposure score penalty, and the
# score-weighting penalties — all sourced from config.py so they can be
# tuned without touching code (see config.SCORE_RISKY_PORTS etc).
_RISKY_PORTS = frozenset(config.SCORE_RISKY_PORTS)
_PENALTY_PER_RISKY_PORT = config.SCORE_PENALTY_PER_RISKY_PORT
_PENALTY_PER_ACTIVE_ATTACK = config.SCORE_PENALTY_PER_ACTIVE_ATTACK


class SecurityScorer:
    """Calculates the composite security score for the monitored network.

    The total score is a weighted average of five components:

    component               weight (default)
    ──────────────────────  ────────────────
    device_security         20 %
    network_health          20 %
    attack_history          25 %
    vulnerability_exposure  20 %
    ai_confidence           15 %
    """

    def __init__(self) -> None:
        self.weights: Dict[str, float] = config.SCORE_WEIGHTS

    # ── public API ──

    def calculate(self) -> Optional[Dict]:
        """Compute, persist, and return the current security score dict."""
        try:
            device_score = self._score_device_security()
            network_score = self._score_network_health()
            attack_score = self._score_attack_history()
            vuln_score = self._score_vulnerability_exposure()
            ai_score = self._score_ai_confidence()

            components = {
                "device_security": round(device_score, 1),
                "network_health": round(network_score, 1),
                "attack_history": round(attack_score, 1),
                "vulnerability_exposure": round(vuln_score, 1),
                "ai_confidence": round(ai_score, 1),
            }

            total = sum(
                components[k] * self.weights.get(k, 0.0)
                for k in components
            )
            total = round(max(0.0, min(100.0, total)), 1)

            trend = self._compute_trend(total)

            db.add_security_score(
                total_score=total,
                device_security=device_score,
                network_health=network_score,
                attack_history=attack_score,
                vulnerability_exposure=vuln_score,
                ai_confidence=ai_score,
                components=components,
                trend=trend,
            )
            logger.info(f"Security score: {total} ({trend})")
            return {"total_score": total, "components": components, "trend": trend}
        except Exception as exc:
            logger.error(f"Security scorer error: {exc}")
            return None

    # ── component scorers ──

    def _score_device_security(self) -> float:
        """100 − penalty for unknown and blocked device ratios."""
        counts = db.get_device_count()
        total = counts.get("total", 0)
        if total == 0:
            return 100.0
        unknown_ratio = counts.get("unknown", 0) / total
        blocked_ratio = counts.get("blocked", 0) / total
        score = 100.0 - (unknown_ratio * 50.0 + blocked_ratio * 20.0)
        return max(0.0, min(100.0, score))

    def _score_network_health(self) -> float:
        """Penalise near-saturation bandwidth and excessive active connections."""
        traffic = db.get_latest_traffic() or {}
        score = 95.0
        bandwidth = traffic.get("bandwidth_mbps", 0.0) or 0.0
        connections = traffic.get("active_connections", 0) or 0

        if bandwidth > 800:      # close to 1 Gbps saturation
            score -= 15.0
        elif bandwidth > 500:
            score -= 5.0

        if connections > 1000:
            score -= 10.0
        elif connections > 500:
            score -= 5.0

        return max(0.0, min(100.0, score))

    def _score_attack_history(self) -> float:
        """100 − 25 per active attack (floored at 0)."""
        active = db.get_active_attacks_count()
        return max(0.0, 100.0 - active * _PENALTY_PER_ACTIVE_ATTACK)

    def _score_vulnerability_exposure(self) -> float:
        """Penalise devices that expose high-risk ports."""
        score = 100.0
        devices = db.get_all_devices()
        for device in devices:
            raw_ports = device.get("open_ports", [])
            # Defensive: handle both list and JSON-string
            if isinstance(raw_ports, str):
                try:
                    raw_ports = json.loads(raw_ports)
                except (json.JSONDecodeError, ValueError):
                    raw_ports = []
            risky = len([p for p in raw_ports if p in _RISKY_PORTS])
            score -= risky * _PENALTY_PER_RISKY_PORT
        return max(0.0, min(100.0, score))

    def _score_ai_confidence(self) -> float:
        """100 if AI is enabled (or setting absent), 50 if explicitly disabled."""
        ai_enabled = db.get_setting("ai_enabled")
        if ai_enabled is not None and ai_enabled.lower() == "false":
            return 50.0
        return 100.0

    # ── trend helper ──

    def _compute_trend(self, current_score: float) -> str:
        """Compare against the previous score to decide improving/stable/declining."""
        history = db.get_score_history(hours=1)
        if not history:
            return "stable"
        prev = history[-1].get("total_score", current_score)
        delta = current_score - prev
        if delta >= 2.0:
            return "improving"
        if delta <= -2.0:
            return "declining"
        return "stable"
