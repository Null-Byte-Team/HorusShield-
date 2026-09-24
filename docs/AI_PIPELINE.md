# AI Pipeline

HorusShield uses four separate, purpose-specific models rather than one general model doing everything — each is small, fast, and interpretable enough to explain its output, which matters for a security tool where an analyst needs to trust *why* something was flagged.

| Module | Technique | Purpose |
|---|---|---|
| `ai/threat_classifier.py` | `sklearn.ensemble.RandomForestClassifier` (100 estimators) | Classifies traffic/events into threat categories |
| `ai/anomaly_detector.py` | `sklearn.ensemble.IsolationForest` | Flags network behavior that deviates from the learned baseline |
| `ai/attack_predictor.py` | `sklearn.neural_network.MLPRegressor` | Predicts near-term attack likelihood |
| `ai/security_scorer.py` | Rule-based weighted scoring (not ML) | Combines device/network/attack/vulnerability/AI-confidence signals into one 0–100 score |

Trained models are persisted to `backend/ai/models/*.joblib` (gitignored — see `.gitignore`). `ai/trainer.py`'s `AITrainer` class retrains them two ways:

- `train_on_history()` — trains on HorusShield's own accumulated database (real traffic/attack/alert history)
- `train_on_synthetic_data()` — generates synthetic examples for cold-start (a fresh install has no history yet)

Triggered via `POST /api/ai/train`, which logs an `ai_analysis` audit-log entry either way.

**First-run note (corrected from an earlier draft of this doc)**: `backend/ai/models/*.joblib` files are gitignored (they're generated artifacts, not source) — a fresh `git clone` or Docker build won't have them. If any model is missing, `_load_model()` catches it, logs a warning, and falls back to a safe default (e.g. `ThreatClassifier.classify()` returns `{"class": "Normal", "probability": 1.0}`) — no crash. But this gap is normally brief: `AITrainer.start()` (called from `app.py`'s `create_app()`) runs a background thread whose `_training_loop()` checks `if self.anomaly_detector.model is None` *before* its first sleep — if so, it immediately calls `train_on_synthetic_data()`. So on a genuinely fresh install, all three models are trained (on synthetic data, not real traffic yet) within moments of the app starting, automatically, with no manual step required. `POST /api/ai/train` is for re-training on real accumulated history later, not for the initial cold start. Training progress is exposed via `GET /api/ai/train/status`; metrics from every training run (real or synthetic) via `GET /api/ai/train/metadata` — see below.

### Training Metadata & Metrics (added in the security/audit pass)

Every training run — cold-start synthetic or later on real history — writes one row to the `model_metadata` table with real, measured metrics, never fabricated ones:

| Model | Metrics reported | Why others are N/A |
|---|---|---|
| `threat_classifier` (RandomForestClassifier) | accuracy, precision, recall, F1, confusion matrix — from a genuine held-out test split | If the training batch has too few samples per class (< 20 samples or < 2 per class) for a meaningful split, no test-set metrics are reported at all — `metrics_note` says so explicitly rather than showing train-set metrics mislabeled as test metrics |
| `attack_predictor` (MLPRegressor) | MSE, MAE, R² | Classification metrics (accuracy/precision/recall/F1) don't apply — this is a regression model, not a classifier. Never reported as if they did. |
| `anomaly_detector` (IsolationForest) | contamination rate (configured), self-flagged-anomaly rate (what fraction of its own training data it flags as anomalous) | No classification metrics — this is unsupervised, trained on normal-only data with no ground-truth labeled anomalies to evaluate precision/recall against. `metrics_note` states this on every row. |

Query real training history: `GET /api/ai/train/metadata?model=threat_classifier&limit=10` (admin/analyst auth required, like every other endpoint — see `docs/SECURITY_ARCHITECTURE.md`).

## Security Score — How It's Actually Calculated

`SecurityScorer.calculate()` combines five weighted components (weights live in `config.py`'s `SCORE_WEIGHTS`, not hardcoded in the scorer itself):

```
total_score = Σ (component_score × weight)
  device_security         × 0.20
  network_health           × 0.20
  attack_history            × 0.25
  vulnerability_exposure     × 0.20
  ai_confidence               × 0.15
```

`vulnerability_exposure` is penalized per open risky port (`SCORE_RISKY_PORTS` in `config.py`, e.g. 22/23/3389/etc — `SCORE_PENALTY_PER_RISKY_PORT` per port) and per active attack (`SCORE_PENALTY_PER_ACTIVE_ATTACK`). The result is clamped to 0–100.

## Horus AI Assistant (`ai/conversation_engine.py`, wrapped by `services/horus_assistant.py`)

Hosted-provider plus deterministic fallback design:

1. **Primary**: if `GEMINI_API_KEY` is set, `_call_gemini()` sends the conversation to Gemini (`gemini-3.6-flash`).
2. **Secondary**: if Gemini is unavailable, `ANTHROPIC_API_KEY` enables Claude (`claude-sonnet-4-20250514`).
3. **Fallback**: if hosted providers are unavailable, a rule-based responder handles common security questions using keyword matching. The chatbot never hard-fails — it degrades to the fallback silently.

Before either hosted call, `_get_security_data()` pulls live numbers straight from the database (security score, device counts, active attacks, recent alerts, honeypot/mesh stats) and the provider adapter includes the safe summary in the prompt. API keys remain server-side and are never sent to the browser.

## V-8 Scanner's "AI Cortex" — Different From the Above, Deliberately

`ai/vscanner_cortex.py` is not a trained model — it's a deterministic, rule-based post-processing layer over findings that OWASP ZAP/Nikto/Nmap already produced:

- **Deduplicate**: hash on `(host, path, normalized finding type)`; corroboration across multiple tools boosts confidence rather than just collapsing duplicates silently.
- **Classify**: maps each finding type to an OWASP Top 10 2021 category + CWE ID via a lookup table (`KNOWLEDGE_BASE` in the same file).
- **Confidence score**: starts from each tool's own reported confidence, adjusted for corroboration.
- **Correlate** (added in the security/audit pass): groups active (non-duplicate) findings that share the same target host/asset but come from *different* tools — e.g. Nmap flagging an open port and ZAP separately flagging a vulnerability reachable through it. This is distinct from deduplication: correlated findings are genuinely different issues, just on the same asset, surfaced together as related context (`correlation_group`, `correlated_with_tools` on each finding) rather than left for an analyst to notice by coincidence.
- **Prioritize**: sorts by severity, then confidence.
- **Explain**: builds a short, concrete, per-finding reasoning string (which tool found it, whether it was corroborated, OWASP/CWE mapping).

This is intentionally *not* a black-box model — every score is traceable to a specific rule, which is a defensible design choice for a security tool's output feeding into a report someone might act on. See `docs/SCANNER_PIPELINE.md` for how findings reach this stage.
