"""
detectors/anomaly.py
────────────────────
Anomaly detection layer using Isolation Forest (scikit-learn).

This is the second layer in the detection engine. It operates independently
from the rules engine — it does not know about keywords or patterns. Instead,
it learns what "normal" looks like from the full dataset's feature vectors,
then flags anything that deviates significantly from that baseline.

Why this matters:
  Rules catch known attacks — patterns you explicitly programmed.
  Anomaly detection catches unknown attacks — novel techniques that no rule
  covers yet. An attacker who avoids all known keywords but still behaves
  unusually will score low on rules but high on anomaly detection.

Pipeline:
  1. fit()      — train the model on all event feature vectors
  2. predict()  — score each event, return anomaly scores
  3. Results feed into scorer.py as anomaly_score

Isolation Forest output:
  The model returns a decision score per event. We normalize this to
  a 0.0–1.0 range so scorer.py can combine it with rule_score uniformly.
  Higher score = more anomalous = higher risk.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from loguru import logger

from features.extractor import EventFeatures


# ── Anomaly Result ────────────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Wraps scikit-learn's IsolationForest for the AiSecPulse pipeline.

    Usage:
        detector = AnomalyDetector(config)
        detector.fit(all_features)
        results = detector.predict(all_features)
    """

    def __init__(self, config: dict):
        """
        Args:
            config: Full config dict from config.yaml.
                    Uses config["anomaly"] section.
        """
        anomaly_cfg = config["anomaly"]

        self.threshold    = anomaly_cfg["threshold"]     # 0.0
        self.model        = IsolationForest(
            contamination = anomaly_cfg["contamination"], # 0.1
            n_estimators  = anomaly_cfg["n_estimators"],  # 100
            random_state  = anomaly_cfg["random_state"],  # 42
        )
        self._fitted = False
        logger.debug("AnomalyDetector initialised")

    def fit(self, features_list: list[EventFeatures]) -> None:
        """
        Train the Isolation Forest on the full dataset's feature vectors.

        The model learns the distribution of normal events. Events that
        deviate from this distribution will receive high anomaly scores.

        In production this would be trained on historical normal traffic only.
        For this project we train on all events — the contamination parameter
        tells the model to expect ~10% anomalies in the training data.

        Args:
            features_list: All EventFeatures from the dataset.
        """
        X = self._to_matrix(features_list)
        logger.info(f"Training Isolation Forest on {len(X)} events...")
        self.model.fit(X)
        self._fitted = True
        logger.info("Isolation Forest trained ✓")

    def predict(self, features_list: list[EventFeatures]) -> list[float]:
        """
        Score each event for anomaly. Returns a list of scores between
        0.0 (normal) and 1.0 (highly anomalous).

        Isolation Forest internally returns decision scores where:
          - Positive values → likely normal
          - Negative values → likely anomalous

        We normalize these to 0.0–1.0 so scorer.py can combine them
        with rule scores on the same scale.

        Args:
            features_list: EventFeatures to score.

        Returns:
            List of float anomaly scores in range [0.0, 1.0],
            in the same order as input.
        """
        if not self._fitted:
            raise RuntimeError("AnomalyDetector must be fitted before calling predict(). Call fit() first.")

        X              = self._to_matrix(features_list)
        raw_scores     = self.model.decision_function(X)
        normalized     = self._normalize(raw_scores)

        flagged = sum(1 for s in normalized if s >= 0.5)
        logger.info(f"Anomaly detection complete — {flagged}/{len(normalized)} events flagged")
        return normalized

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _to_matrix(self, features_list: list[EventFeatures]) -> np.ndarray:
        """
        Convert a list of EventFeatures into a 2D numpy matrix.

        Each row is one event's feature vector [7 values].
        This is the format scikit-learn expects.

        Args:
            features_list: List of EventFeatures objects.

        Returns:
            numpy array of shape (n_events, 7).
        """
        return np.array([f.to_vector() for f in features_list])

    def _normalize(self, raw_scores: np.ndarray) -> list[float]:
        """
        Normalize Isolation Forest decision scores to [0.0, 1.0].

        Isolation Forest scores have no fixed range — they depend on the
        data distribution. We use min-max normalization and then invert
        the scale so that:
          - Most anomalous (lowest raw score) → 1.0
          - Most normal (highest raw score)   → 0.0

        Formula:
            normalized = 1 - (score - min) / (max - min)

        Edge case: if all scores are identical (flat data), return 0.0
        for all events to avoid division by zero.

        Args:
            raw_scores: 1D numpy array of raw Isolation Forest scores.

        Returns:
            List of floats in [0.0, 1.0].
        """
        min_score = raw_scores.min()
        max_score = raw_scores.max()

        if max_score == min_score:
            logger.warning("All anomaly scores identical — returning 0.0 for all events")
            return [0.0] * len(raw_scores)

        normalized = 1.0 - (raw_scores - min_score) / (max_score - min_score)
        return [round(float(s), 4) for s in normalized]