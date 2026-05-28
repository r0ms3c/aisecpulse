"""
main.py
───────
Entry point for the AiSecPulse detection pipeline.

Runs the full pipeline in order:
  Phase 1 — ETL       : Load and normalize events
  Phase 2 — Features  : Extract features per event        (coming next)
  Phase 3 — Detection : Run rule + anomaly detectors      (coming next)
  Phase 4 — Output    : Generate alerts and HTML report   (coming next)

Usage:
    python3 main.py
"""

import sys
import yaml
from loguru import logger

from etl.ingest    import load_events
from etl.normalize import normalize_events

# ── Logging setup ─────────────────────────────────────────────────────────────
# Two handlers:
#   1. stdout  — so you can see output in the terminal while developing
#   2. log file — so detections are persisted in logs/detections.log
# When the project is finished, handler 1 can be removed to run silently.
logger.remove()
logger.add(
    sys.stdout,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}"
)
logger.add(
    "logs/detections.log",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}",
    rotation="1 MB",     # start a new file when it reaches 1 MB
    retention="7 days",  # keep logs for 7 days then delete
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

    # Summary breakdown
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
    # TODO: Will be implemented in Phase 2
    logger.info("── Phase 2: Feature Engineering — coming next ────────────")

    # ── Phase 3: Detection Engine ─────────────────────────────────────────────
    # TODO: Will be implemented in Phase 3
    logger.info("── Phase 3: Detection Engine — coming next ───────────────")

    # ── Phase 4: Alerts + Report ──────────────────────────────────────────────
    # TODO: Will be implemented in Phase 4
    logger.info("── Phase 4: Alerts + Report — coming next ────────────────")


if __name__ == "__main__":
    main()