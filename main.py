"""
main.py
───────
Entry point for the AiSecPulse detection pipeline.

Runs the full pipeline in order:
  Phase 1 — ETL       : Load and normalize events
  Phase 2 — Features  : Extract features per event
  Phase 3 — Detection : Run rule + anomaly detectors      (coming next)
  Phase 4 — Output    : Generate alerts and HTML report   (coming next)

Usage:
    python3 main.py
"""

import sys
import yaml
from loguru import logger

from etl.ingest         import load_events
from etl.normalize      import normalize_events
from features.extractor import FeatureExtractor
from detectors.rules       import RulesDetector

# ── Logging setup ─────────────────────────────────────────────────────────────
# Two handlers:
#   1. stdout  — visible in terminal while developing
#   2. log file — persisted to logs/detections.log
# When the project is finished, handler 1 can be removed to run silently.
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
    """Load configuration from config.yaml."""
    with open(path, "r") as f:
        return yaml.safe_load(f)


def main():
    logger.info("=" * 60)
    logger.info("AiSecPulse — AI Security Detection Pipeline")
    logger.info("=" * 60)

    # ── Load configuration ────────────────────────────────────────────────────
    config = load_config()
    logger.info("Configuration loaded")

    # ── Phase 1: ETL ──────────────────────────────────────────────────────────
    logger.info("── Phase 1: ETL ──────────────────────────────────────────")

    raw_events = load_events(config["data"]["sample_file"])
    events     = normalize_events(raw_events)

    chat_events      = [e for e in events if e.type == "chat"]
    agent_events     = [e for e in events if e.type == "agent"]
    normal_events    = [e for e in events if e.label == "normal"]
    injection_events = [e for e in events if e.label == "injection"]

    logger.info(f"Total events   : {len(events)}")
    logger.info(f"  Chat         : {len(chat_events)}")
    logger.info(f"  Agent        : {len(agent_events)}")
    logger.info(f"  Normal       : {len(normal_events)}")
    logger.info(f"  Injection    : {len(injection_events)}")
    logger.info("Phase 1 complete ✓")

    # ── Phase 2: Feature Engineering ─────────────────────────────────────────
    logger.info("── Phase 2: Feature Engineering ──────────────────────────")

    extractor     = FeatureExtractor(config)
    all_features  = extractor.extract_all(events)

    # Print a sample — first 3 normal and first 3 injection events
    logger.info("Sample feature vectors (normal events):")
    normal_indices = [i for i, e in enumerate(events) if e.label == "normal"][:3]
    for i in normal_indices:
        f = all_features[i]
        logger.info(
            f"  [{events[i].user_id}] vector={f.to_vector()} "
            f"label={events[i].label}"
        )

    logger.info("Sample feature vectors (injection events):")
    injection_indices = [i for i, e in enumerate(events) if e.label == "injection"][:3]
    for i in injection_indices:
        f = all_features[i]
        logger.info(
            f"  [{events[i].user_id}] vector={f.to_vector()} "
            f"label={events[i].label}"
        )

    logger.info("Phase 2 complete ✓")

    # ── Phase 3: Detection Engine ─────────────────────────────────────────────
    # TODO: Will be implemented in Phase 3
    logger.info("── Phase 3: Detection Engine ───────────────")
    
    # Layer 1 — Rules
    rules_detector = RulesDetector(config)
    rule_results   = rules_detector.evaluate_all(all_features)

    logger.info(f"rule_results: {rule_results}")

    # ── Phase 4: Alerts + Report ──────────────────────────────────────────────
    # TODO: Will be implemented in Phase 4
    logger.info("── Phase 4: Alerts + Report — coming next ────────────────")


if __name__ == "__main__":
    main()