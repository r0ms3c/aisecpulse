"""
alerts/alerting.py
──────────────────
Generates structured alert objects from DetectionResult outputs.

This module is the bridge between the detection engine and the output
layer (logger + HTML report). It takes raw DetectionResult objects,
enriches them with event context, and produces Alert objects that
carry everything needed to understand what happened and why.

Only events with severity HIGH or CRITICAL produce alerts.
LOW and MEDIUM events are tracked in the summary but not alerted.
"""

from dataclasses import dataclass, field
from loguru import logger

from etl.normalize     import Event
from detectors.scorer  import DetectionResult


# ── Alert ─────────────────────────────────────────────────────────────────────

@dataclass
class Alert:
    """
    A fully enriched alert for a single detected event.

    Carries everything needed for the report and logs — no need to
    cross-reference the original event after this point.

    Attributes:
        timestamp     : When the event occurred
        user_id       : User or agent that triggered the event
        event_type    : "chat" or "agent"
        prompt        : The input that triggered the alert
        action        : Agent action if applicable, None for chat
        severity      : "HIGH" or "CRITICAL"
        final_score   : Combined risk score (0.0–1.0)
        rule_score    : Score from the rules layer
        anomaly_score : Score from the anomaly layer
        reasons       : Rule names that fired (empty if anomaly-only)
        detection_type: How the alert was triggered
    """
    timestamp      : str
    user_id        : str
    event_type     : str
    prompt         : str
    action         : str | None
    severity       : str
    final_score    : float
    rule_score     : float
    anomaly_score  : float
    reasons        : list[str] = field(default_factory=list)
    detection_type : str       = ""

    def __post_init__(self):
        """Classify detection type based on which layers fired."""
        rule_fired    = self.rule_score > 0.0
        anomaly_fired = self.anomaly_score >= 0.5

        if rule_fired and anomaly_fired:
            self.detection_type = "rule + anomaly"
        elif rule_fired:
            self.detection_type = "rule"
        elif anomaly_fired:
            self.detection_type = "anomaly"
        else:
            self.detection_type = "unknown"


# ── Alert Generator ───────────────────────────────────────────────────────────

class AlertGenerator:
    """
    Processes detection results and produces Alert objects.

    Instantiate once, call generate_all() with the full dataset results.
    """

    def __init__(self, config: dict):
        self.config = config
        logger.debug("AlertGenerator initialised")

    def generate_all(
        self,
        events  : list[Event],
        results : list[DetectionResult],
    ) -> list[Alert]:
        """
        Generate alerts for all events that scored HIGH or CRITICAL.

        Args:
            events  : Normalized events from ETL pipeline
            results : DetectionResult list from Scorer.score_all()

        Returns:
            List of Alert objects, ordered by final_score descending.
        """
        alerts = []

        for event, result in zip(events, results):
            if result.alert:
                alert = Alert(
                    timestamp     = event.timestamp,
                    user_id       = event.user_id,
                    event_type    = event.type,
                    prompt        = event.prompt,
                    action        = event.action,
                    severity      = result.severity,
                    final_score   = result.final_score,
                    rule_score    = result.rule_score,
                    anomaly_score = result.anomaly_score,
                    reasons       = result.reasons,
                )
                alerts.append(alert)

        # Sort by final score descending — most critical first
        alerts.sort(key=lambda a: a.final_score, reverse=True)

        # Summary log
        critical = sum(1 for a in alerts if a.severity == "CRITICAL")
        high     = sum(1 for a in alerts if a.severity == "HIGH")
        logger.info(f"Alerts generated — CRITICAL={critical} | HIGH={high} | Total={len(alerts)}")

        # Log each alert
        for alert in alerts:
            logger.warning(
                f"[{alert.severity}] {alert.event_type} | {alert.user_id} | "
                f"score={alert.final_score} | type={alert.detection_type} | "
                f"rules={alert.reasons}"
            )

        return alerts