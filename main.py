"""
main.py
───────
Entry point for the AiSecPulse detection pipeline.

Runs the full pipeline in order:
  Phase 1 — ETL       : Load and normalize events
  Phase 2 — Features  : Extract features per event
  Phase 3 — Detection : Run rule + anomaly detectors
  Phase 4 — Output    : Generate alerts and HTML report

Usage:
    python3 main.py
"""

import sys
import yaml
from loguru import logger

from etl.ingest            import load_events
from etl.normalize         import normalize_events
from features.extractor    import FeatureExtractor
from detectors.rules       import RulesDetector
from detectors.anomaly     import AnomalyDetector
from detectors.scorer      import Scorer
from alerts.alerting       import AlertGenerator
from reports.generator     import ReportGenerator

# ── Logging setup ─────────────────────────────────────────────────────────────
# stdout  — visible in terminal while developing
# log file — persisted to logs/detections.log
logger.remove()
logger.add(
    sys.stdout,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}"
)
logger.add(
    "logs/detections.log",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}",
    rotation="1 MB",
    retention="7 days",
    encoding="utf-8"
)


def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def main():
    logger.info("=" * 60)
    logger.info("AiSecPulse — AI Security Detection Pipeline")
    logger.info("=" * 60)

    config = load_config()
    logger.info("Configuration loaded")

    # ── Phase 1: ETL ──────────────────────────────────────────────────────────
    logger.info("── Phase 1: ETL ──────────────────────────────────────────")
    raw_events = load_events(config["data"]["sample_file"])
    events     = normalize_events(raw_events)
    logger.info(
        f"Total events: {len(events)} "
        f"(chat={sum(1 for e in events if e.type=='chat')} "
        f"agent={sum(1 for e in events if e.type=='agent')})"
    )
    logger.info("Phase 1 complete ✓")

    # ── Phase 2: Feature Engineering ─────────────────────────────────────────
    logger.info("── Phase 2: Feature Engineering ──────────────────────────")
    extractor    = FeatureExtractor(config)
    all_features = extractor.extract_all(events)
    logger.info("Phase 2 complete ✓")

    # ── Phase 3: Detection Engine ─────────────────────────────────────────────
    logger.info("── Phase 3: Detection Engine ─────────────────────────────")

    rules_detector   = RulesDetector(config)
    rule_results     = rules_detector.evaluate_all(all_features)

    anomaly_detector = AnomalyDetector(config)
    anomaly_detector.fit(all_features)
    anomaly_scores   = anomaly_detector.predict(all_features)

    scorer  = Scorer(config)
    results = scorer.score_all(rule_results, anomaly_scores)
    logger.info("Phase 3 complete ✓")

    # ── Phase 4: Alerts + Report ──────────────────────────────────────────────
    logger.info("── Phase 4: Alerts + Report ──────────────────────────────")

    alert_gen = AlertGenerator(config)
    alerts    = alert_gen.generate_all(events, results)

    report_gen   = ReportGenerator(config)
    report_path  = report_gen.generate(events, results, alerts)

    logger.info("=" * 60)
    logger.info(f"Pipeline complete — {len(alerts)} alerts raised")
    logger.info(f"Report → {report_path}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()