"""
etl/normalize.py
────────────────
Responsible for validating and normalizing raw events loaded by ingest.py.
 
Every event coming out of this module is guaranteed to:
  - Have all required fields present
  - Have correct types for each field
  - Have a valid label ("normal" or "injection")
  - Have a valid type ("chat" or "agent")
  - Have null-safe optional fields (action defaults to None)
 
Events that fail validation are skipped with a warning — the pipeline never
crashes on a single bad record.
"""

from dataclasses import dataclass
from typing import Optional
from loguru import logger


# ── Event Schema ──────────────────────────────────────────────────────────────

@dataclass
class Event:
    """
    Unified event schema for AiSecPulse.
 
    Every event in the pipeline — whether from a chatbot or an agentic system —
    is normalized into this structure before any detection logic runs.
 
    Fields:
        timestamp   : ISO 8601 datetime string when the event occurred.
        source      : Origin of the event (e.g. "sample", "production").
        type        : "chat" for human↔AI interactions,
                      "agent" for AI→API/action events.
        user_id     : Identifier of the user or agent that generated the event.
        prompt      : The input sent to the AI system.
        response    : The AI system's output (may be empty for blocked actions).
        action      : The action the agent attempted to execute.
                      None for chat events — only populated for agent events.
        label       : Ground truth label for evaluation.
                      "normal"    → legitimate interaction
                      "injection" → attack or malicious attempt
    """
    timestamp : str
    source    : str
    type      : str
    user_id   : str
    prompt    : str
    response  : str
    action    : Optional[str]
    label     : str


# ── Required fields and allowed values ───────────────────────────────────────
REQUIRED_FIELDS  = ["timestamp", "source", "type", "user_id", "prompt", "response", "label"]
ALLOWED_TYPES    = {"chat", "agent"}
ALLOWED_LABELS   = {"normal", "injection"}

# ── Normalization ─────────────────────────────────────────────────────────────

def normalize_events(raw_events: list[dict]) -> list[Event]:
    """
    Validate and normalize a list of raw event dictionaries into Event objects.
 
    Skips any event that fails validation, logging the reason and the index.
    Returns only the events that passed — the pipeline continues cleanly.
 
    Args:
        raw_events: List of raw dicts from ingest.load_events()
 
    Returns:
        List of validated, normalized Event objects.
    """

    normalize = []
    skipped   = 0

    for i, raw in enumerate(raw_events):
        event = _validate_and_build(raw, index=i)
        if event is not None:
            normalize.append(event)
        else:
            skipped += 1

    logger.info(f"Normalization complete — {len(normalize)} valid events, {skipped} skipped")
    return normalize

def _validate_and_build(raw: dict, index: int) -> Optional[Event]:
    """
    Validate a single raw event dict and build an Event dataclass from it.
 
    Args:
        raw   : Raw event dictionary from the JSON file.
        index : Position in the original list, used for logging only.
 
    Returns:
        A valid Event object, or None if validation fails.
    """
     # ── Check all required fields are present ────────────────────────────────
    for field in REQUIRED_FIELDS:
        if field not in raw:
            logger.warning(f"Event #{index} skipped — missing required field: '{field}'")
            return None
        
    # ── Validate allowed values ───────────────────────────────────────────────
    event_type = str(raw["type"]).strip().lower()
    if event_type not in ALLOWED_TYPES:
        logger.warning(
            f"Event #{index} skipped — invalid type: '{raw['type']}' "
            f"(expected one of {ALLOWED_TYPES})"
        )
        return None
    
    label = str(raw["label"]).strip().lower()
    if label not in ALLOWED_LABELS:
        logger.warning(
            f"Event #{index} skipped — invalid label: '{raw['label']}' "
            f"(expected one of {ALLOWED_LABELS})"
        )
        return None
    

    # ── Null-safe optional field ──────────────────────────────────────────────
    # action is only present on agent events. Chat events will have null/None.
    # We normalise both cases to Python None so downstream code never sees
    # missing keys or unexpected types.
    action = raw.get("action")
    if action is not None and not isinstance(action, str):
        action = str(action)

    # ── Build and return the Event ────────────────────────────────────────────
    return Event(
        timestamp = str(raw["timestamp"]).strip(),
        source    = str(raw["source"]).strip(),
        type      = event_type,
        user_id   = str(raw["user_id"]).strip(),
        prompt    = str(raw["prompt"]).strip(),
        response  = str(raw["response"]).strip(),
        action    = action,
        label     = label,

    )


