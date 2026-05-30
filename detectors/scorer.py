"""
detectors/scorer.py
───────────────────
Combines rule_score and anomaly_score into a single final risk score
and maps it to a human-readable severity level.

This is the final step of the detection engine before alerting.
It takes the outputs of rules.py and anomaly.py and produces one
unified verdict per event.

Formula:
    final_score = (rule_score × rule_weight) + (anomaly_score × anomaly_weight)

    Weights come from config.yaml → scorer section (default: 0.65 / 0.35).

Severity mapping (from config.yaml → thresholds):
    0.00 – 0.39  →  LOW       no alert
    0.40 – 0.69  →  MEDIUM    logged, worth reviewing
    0.70 – 0.89  →  HIGH      alert raised
    0.90 – 1.00  →  CRITICAL  alert raised and flagged
"""

from dataclasses import dataclass, field
from loguru import logger

from detectors.rules   import RuleResult


# ── Detection Result ──────────────────────────────────────────────────────────

@dataclass
class DetectionResult:
    """
    Final detection verdict for a single event.

    This is the output that flows into alerting.py and the HTML report.

    Attributes:
        rule_score    : Score from the rules engine (0.0–1.0)
        anomaly_score : Score from the anomaly detector (0.0–1.0)
        final_score   : Weighted combination of both scores (0.0–1.0)
        severity      : Human-readable severity level
        alert         : True if severity is HIGH or CRITICAL
        reasons       : Rule names that fired (from RuleResult.reasons)
    """
    rule_score    : float
    anomaly_score : float
    final_score   : float
    severity      : str
    alert         : bool
    reasons       : list[str] = field(default_factory=list)


# ── Scorer ────────────────────────────────────────────────────────────────────

class Scorer:
    """
    Combines detection signals and classifies severity.

    Instantiate once with config, call score() per event or
    score_all() for the full dataset.
    """

    def __init__(self, config: dict):
        """
        Args:
            config: Full config dict from config.yaml.
                    Uses config["scorer"] and config["thresholds"].
        """
        scorer_cfg     = config["scorer"]
        threshold_cfg  = config["thresholds"]

        self.rule_weight    = scorer_cfg["rule_weight"]     # 0.65
        self.anomaly_weight = scorer_cfg["anomaly_weight"]  # 0.35

        self.thresh_low      = threshold_cfg["low"]       # 0.39
        self.thresh_medium   = threshold_cfg["medium"]    # 0.69
        self.thresh_high     = threshold_cfg["high"]      # 0.89

        logger.debug("Scorer initialised")

    def score(self, rule_result: RuleResult, anomaly_score: float) -> DetectionResult:
        """
        Combine a RuleResult and anomaly score into a DetectionResult.

        Args:
            rule_result   : Output of RulesDetector.evaluate()
            anomaly_score : Single float from AnomalyDetector.predict()

        Returns:
            DetectionResult with final score, severity, and alert flag.
        """
        final_score = (
            rule_result.score * self.rule_weight +
            anomaly_score     * self.anomaly_weight
        )
        final_score = round(min(final_score, 1.0), 4)
        severity    = self._classify(final_score)
        alert       = severity in {"HIGH", "CRITICAL"}

        return DetectionResult(
            rule_score    = rule_result.score,
            anomaly_score = round(anomaly_score, 4),
            final_score   = final_score,
            severity      = severity,
            alert         = alert,
            reasons       = rule_result.reasons,
        )

    def score_all(
        self,
        rule_results   : list[RuleResult],
        anomaly_scores : list[float],
    ) -> list[DetectionResult]:
        """
        Score all events in the dataset.

        Args:
            rule_results   : List of RuleResult from RulesDetector.evaluate_all()
            anomaly_scores : List of floats from AnomalyDetector.predict()

        Returns:
            List of DetectionResult in the same order as inputs.
        """
        if len(rule_results) != len(anomaly_scores):
            raise ValueError(
                f"Mismatched lengths: {len(rule_results)} rule results "
                f"vs {len(anomaly_scores)} anomaly scores"
            )

        results = [
            self.score(rule_result, anomaly_score)
            for rule_result, anomaly_score in zip(rule_results, anomaly_scores)
        ]

        # Summary breakdown
        breakdown = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for r in results:
            breakdown[r.severity] += 1

        alerts = sum(1 for r in results if r.alert)
        logger.info(
            f"Scoring complete — "
            f"LOW={breakdown['LOW']} | "
            f"MEDIUM={breakdown['MEDIUM']} | "
            f"HIGH={breakdown['HIGH']} | "
            f"CRITICAL={breakdown['CRITICAL']} | "
            f"Alerts={alerts}"
        )
        return results

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _classify(self, score: float) -> str:
        """
        Map a numeric score to a severity label.

        Args:
            score: Final risk score in [0.0, 1.0]

        Returns:
            One of: "LOW", "MEDIUM", "HIGH", "CRITICAL"
        """
        if score <= self.thresh_low:
            return "LOW"
        elif score <= self.thresh_medium:
            return "MEDIUM"
        elif score <= self.thresh_high:
            return "HIGH"
        else:
            return "CRITICAL"