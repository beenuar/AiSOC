"""
ML-based anomaly and priority scoring for alerts.

Anomaly score  — Isolation Forest trained on alert feature vectors.
                 Outputs 0.0 (normal) → 1.0 (highly anomalous).

Priority score — LightGBM ranker trained on analyst feedback signals
                 (true-positive labels + assigned priority).
                 Outputs 0.0 → 1.0 (higher = more urgent).

Both models are held in memory and retrained on demand when enough
feedback accumulates. They fall back to heuristics if not yet trained.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import asyncio
import math
from datetime import datetime
from typing import Any

import structlog

from app.models.alert import AnalystFeedback, FusedAlert, RawAlert

logger = structlog.get_logger()

# ─────────────────────────────────────────────────────────────────────────────
# Feature engineering helpers
# ─────────────────────────────────────────────────────────────────────────────

_SEVERITY_MAP = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _featurize(alert: RawAlert) -> list[float]:
    """Convert a RawAlert to a fixed-length numeric feature vector."""
    sev = _SEVERITY_MAP.get(alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity), 2)
    has_src_ip = 1.0 if alert.src_ip else 0.0
    has_dst_ip = 1.0 if alert.dst_ip else 0.0
    has_hostname = 1.0 if alert.hostname else 0.0
    has_username = 1.0 if alert.username else 0.0
    has_file_hash = 1.0 if alert.file_hash else 0.0
    has_domain = 1.0 if alert.domain else 0.0
    has_url = 1.0 if alert.url else 0.0
    num_tactics = float(len(alert.mitre_tactics))
    num_techniques = float(len(alert.mitre_techniques))
    num_tags = float(len(alert.tags))
    risk_score = float(alert.risk_score) if alert.risk_score else 0.0
    hour_of_day = float(alert.created_at.hour) if alert.created_at else 12.0
    return [
        float(sev),
        has_src_ip,
        has_dst_ip,
        has_hostname,
        has_username,
        has_file_hash,
        has_domain,
        has_url,
        num_tactics,
        num_techniques,
        num_tags,
        risk_score,
        hour_of_day,
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Heuristic fallbacks (used when ML models aren't trained yet)
# ─────────────────────────────────────────────────────────────────────────────


def _heuristic_anomaly(alert: RawAlert) -> float:
    """Simple heuristic anomaly score: more IOC fields = potentially more anomalous."""
    score = 0.0
    if alert.file_hash:
        score += 0.3
    if alert.src_ip and alert.dst_ip:
        score += 0.2
    if len(alert.mitre_techniques) > 2:
        score += min(0.3, len(alert.mitre_techniques) * 0.05)
    sev = _SEVERITY_MAP.get(alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity), 2)
    score += sev * 0.05
    return min(score, 1.0)


def _heuristic_priority(alert: RawAlert) -> float:
    """Simple heuristic priority score based on severity and IOC density."""
    sev = _SEVERITY_MAP.get(alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity), 2)
    base = sev / 4.0
    ioc_bonus = sum(
        [
            0.1 if alert.src_ip else 0.0,
            0.05 if alert.hostname else 0.0,
            0.05 if alert.username else 0.0,
            0.1 if alert.file_hash else 0.0,
            0.05 if alert.mitre_techniques else 0.0,
        ]
    )
    return min(base + ioc_bonus, 1.0)


# ─────────────────────────────────────────────────────────────────────────────
# MLScorer class
# ─────────────────────────────────────────────────────────────────────────────

_MIN_SAMPLES_FOR_TRAINING = 50
_MIN_FEEDBACK_FOR_RANKER = 30


class MLScorer:
    """
    Wraps scikit-learn Isolation Forest + LightGBM LambdaRank for alert scoring.

    Models are trained lazily once enough data accumulates. Until then,
    heuristic fallbacks are used so the service is always available.
    """

    def __init__(self) -> None:
        self._iso_forest = None  # sklearn IsolationForest
        self._lgbm_ranker = None  # lightgbm LGBMRanker
        self._iso_trained = False
        self._lgbm_trained = False

        # Rolling in-memory training buffers
        self._feature_buffer: list[list[float]] = []
        self._feedback_buffer: list[dict[str, Any]] = []

        self._lock = asyncio.Lock()

    # ─── Public API ──────────────────────────────────────────────────────────

    async def score(self, fused_alert: FusedAlert) -> FusedAlert:
        """Compute and attach anomaly_score and priority_score to the fused alert."""
        alert = fused_alert.alert
        features = _featurize(alert)

        # Buffer features for future training
        async with self._lock:
            self._feature_buffer.append(features)

        if self._iso_trained and self._iso_forest is not None:
            anomaly_score = await asyncio.get_event_loop().run_in_executor(None, self._predict_anomaly, features)
        else:
            anomaly_score = _heuristic_anomaly(alert)

        if self._lgbm_trained and self._lgbm_ranker is not None:
            priority_score = await asyncio.get_event_loop().run_in_executor(None, self._predict_priority, features)
        else:
            priority_score = _heuristic_priority(alert)

        fused_alert.anomaly_score = round(anomaly_score, 4)
        fused_alert.priority_score = round(priority_score, 4)

        logger.debug(
            "ML scores computed",
            alert_id=str(fused_alert.id),
            anomaly_score=fused_alert.anomaly_score,
            priority_score=fused_alert.priority_score,
            iso_trained=self._iso_trained,
            lgbm_trained=self._lgbm_trained,
        )
        return fused_alert

    async def record_feedback(self, feedback: AnalystFeedback) -> None:
        """Record analyst feedback and trigger re-training if threshold reached."""
        async with self._lock:
            self._feedback_buffer.append(feedback.model_dump(mode="json"))

        # Trigger background re-training checks
        await self._maybe_retrain()

    async def retrain(self) -> dict[str, Any]:
        """Force a re-training of both models. Returns training summary."""
        async with self._lock:
            features = list(self._feature_buffer)
            feedback = list(self._feedback_buffer)

        iso_result = await asyncio.get_event_loop().run_in_executor(None, self._train_isolation_forest, features)
        lgbm_result = await asyncio.get_event_loop().run_in_executor(None, self._train_lgbm_ranker, features, feedback)

        return {
            "isolation_forest": iso_result,
            "lgbm_ranker": lgbm_result,
            "feature_samples": len(features),
            "feedback_samples": len(feedback),
            "retrained_at": datetime.utcnow().isoformat(),
        }

    def status(self) -> dict[str, Any]:
        """Return current model status."""
        return {
            "isolation_forest_trained": self._iso_trained,
            "lgbm_ranker_trained": self._lgbm_trained,
            "feature_buffer_size": len(self._feature_buffer),
            "feedback_buffer_size": len(self._feedback_buffer),
            "min_samples_for_iso": _MIN_SAMPLES_FOR_TRAINING,
            "min_feedback_for_lgbm": _MIN_FEEDBACK_FOR_RANKER,
        }

    # ─── Private: predictions ────────────────────────────────────────────────

    def _predict_anomaly(self, features: list[float]) -> float:
        """Run IsolationForest prediction synchronously."""
        try:
            import numpy as np

            X = np.array(features).reshape(1, -1)
            # decision_function: negative = anomaly, normalize to [0,1]
            raw = self._iso_forest.decision_function(X)[0]
            # Map decision score: lower = more anomalous
            # Typical range is -0.5 to +0.5; map to 0→1 (inverted)
            score = 1.0 / (1.0 + math.exp(5 * raw))  # sigmoid inversion
            return float(score)
        except Exception as exc:
            logger.warning("IsolationForest predict error", error=str(exc))
            return 0.0

    def _predict_priority(self, features: list[float]) -> float:
        """Run LightGBM ranker prediction synchronously."""
        try:
            import numpy as np

            X = np.array(features).reshape(1, -1)
            raw = self._lgbm_ranker.predict(X)[0]
            # Normalize to [0,1] via sigmoid
            score = 1.0 / (1.0 + math.exp(-raw))
            return float(score)
        except Exception as exc:
            logger.warning("LightGBM predict error", error=str(exc))
            return 0.0

    # ─── Private: training ───────────────────────────────────────────────────

    def _train_isolation_forest(self, features: list[list[float]]) -> dict[str, Any]:
        """Train Isolation Forest on accumulated feature vectors."""
        if len(features) < _MIN_SAMPLES_FOR_TRAINING:
            return {"status": "skipped", "reason": f"need {_MIN_SAMPLES_FOR_TRAINING} samples, have {len(features)}"}
        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest

            X = np.array(features)
            model = IsolationForest(
                n_estimators=200,
                contamination=0.1,
                random_state=42,
                n_jobs=-1,
            )
            model.fit(X)
            self._iso_forest = model
            self._iso_trained = True
            logger.info("IsolationForest retrained", samples=len(features))
            return {"status": "trained", "samples": len(features)}
        except Exception as exc:
            logger.error("IsolationForest training failed", error=str(exc))
            return {"status": "error", "error": str(exc)}

    def _train_lgbm_ranker(
        self,
        features: list[list[float]],
        feedback: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Train LightGBM ranker on analyst feedback."""
        if len(feedback) < _MIN_FEEDBACK_FOR_RANKER:
            return {"status": "skipped", "reason": f"need {_MIN_FEEDBACK_FOR_RANKER} feedback items, have {len(feedback)}"}
        try:
            import lightgbm as lgb
            import numpy as np

            # Build training set from feedback + heuristic features
            X_rows = []
            y_rows = []
            qid_rows = []

            for i, fb in enumerate(feedback):
                # Use heuristic features if no stored features match
                feat = features[i % len(features)] if features else [0.0] * 13

                is_tp = 1.0 if fb.get("is_true_positive", False) else 0.0
                # assigned_priority 1 (critical) → 5 (low) — invert to relevance 4 → 0
                priority_rel = max(0, 5 - int(fb.get("assigned_priority", 3)))
                relevance = int(is_tp * 2 + priority_rel)

                X_rows.append(feat)
                y_rows.append(relevance)
                qid_rows.append(0)  # single query group

            X = np.array(X_rows)
            y = np.array(y_rows, dtype=int)
            groups = [len(y_rows)]

            model = lgb.LGBMRanker(
                objective="lambdarank",
                metric="ndcg",
                n_estimators=200,
                learning_rate=0.05,
                num_leaves=31,
                random_state=42,
                verbose=-1,
            )
            model.fit(X, y, group=groups)
            self._lgbm_ranker = model
            self._lgbm_trained = True
            logger.info("LightGBM ranker retrained", feedback_samples=len(feedback))
            return {"status": "trained", "feedback_samples": len(feedback)}
        except Exception as exc:
            logger.error("LightGBM training failed", error=str(exc))
            return {"status": "error", "error": str(exc)}

    # ─── Private: auto-retrain ────────────────────────────────────────────────

    async def _maybe_retrain(self) -> None:
        """Trigger retraining if thresholds are met."""
        async with self._lock:
            n_features = len(self._feature_buffer)
            n_feedback = len(self._feedback_buffer)

        should_iso = (not self._iso_trained and n_features >= _MIN_SAMPLES_FOR_TRAINING) or (self._iso_trained and n_features % 500 == 0)
        should_lgbm = (not self._lgbm_trained and n_feedback >= _MIN_FEEDBACK_FOR_RANKER) or (self._lgbm_trained and n_feedback % 100 == 0)

        if should_iso or should_lgbm:
            asyncio.create_task(self._retrain_background(should_iso, should_lgbm))

    async def _retrain_background(self, do_iso: bool, do_lgbm: bool) -> None:
        """Background task: run training without blocking request handling."""
        async with self._lock:
            features = list(self._feature_buffer)
            feedback = list(self._feedback_buffer)

        loop = asyncio.get_event_loop()
        if do_iso:
            await loop.run_in_executor(None, self._train_isolation_forest, features)
        if do_lgbm:
            await loop.run_in_executor(None, self._train_lgbm_ranker, features, feedback)
