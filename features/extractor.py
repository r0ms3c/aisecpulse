"""
features/extractor.py
─────────────────────
Extracts a numeric feature vector from each normalized Event.
 
This is the bridge between raw events and the detection engine.
Both detectors/rules.py and detectors/anomaly.py work from these
features — rules use individual flags directly, anomaly detection
uses the full vector as input to Isolation Forest.
 
Feature vector (7 values per event):
    [0] prompt_length_band      — 0 (short) to 3 (very long)
    [1] keyword_hit             — 1 if injection keyword found in prompt
    [2] instruction_density     — 1 if imperative verb ratio exceeds threshold
    [3] has_zero_width_chars    — 1 if obfuscation via invisible unicode detected
    [4] has_base64_content      — 1 if base64-encoded payload detected
    [5] is_agent_event          — 1 if event.type == "agent"
    [6] has_dangerous_action    — 1 if agent action matches a dangerous pattern
 
All values are integers (0 or 1) except prompt_length_band (0–3),
making the vector fully numeric and ready for scikit-learn.
"""

import re
import base64
from dataclasses import dataclass

from loguru import logger

from etl.normalize import Event

# ── Feature Result ────────────────────────────────────────────────────────────

@dataclass
class EventFeatures:
    """
    Feature vector for a single event.
 
    Stores both the numeric vector (for the anomaly detector) and
    the individual named flags (for the rules engine and logging).
    """
    #Named features — used directly by rules.py and for human-readable output
    prompt_length_band    : int   # 0=short, 1=medium, 2=long, 3=very long
    keyword_hit           : int   # 1 if injection keyword matched
    instruction_density   : int   # 1 if imperative verb ratio is high
    has_zero_width_chars  : int   # 1 if invisible unicode chars detected
    has_base64_content    : int   # 1 if base64-encoded content detected
    is_agent_event        : int   # 1 if event type is "agent"
    has_dangerous_action  : int   # 1 if agent action is dangerous

    def to_vector(self) -> list[int]:
        """
        Return features as a flat numeric list for the anomaly detector.
        Order must stay consistent — Isolation Forest is position-sensitive.
        """
        return [
            self.prompt_length_band,
            self.keyword_hit,
            self.instruction_density,
            self.has_zero_width_chars,
            self.has_base64_content,
            self.is_agent_event,
            self.has_dangerous_action,
        ]
    
# ── Zero-width unicode characters used for obfuscation ───────────────────────
# Attackers insert these invisible characters between letters to break
# simple keyword matching. They are invisible to the human eye but
# detectable programmatically by checking the unicode category.

ZERO_WIDTH_CHARS = {
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero-width no-break space (BOM)
}

# ── Base64 pattern ────────────────────────────────────────────────────────────
# Matches strings that look like base64 encoded content.
# Requires at least one = padding character to reduce false positives
# on normal alphanumeric tokens.
BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={1,2}")


# ── Extractor ─────────────────────────────────────────────────────────────────
class FeatureExtractor:
    """
    Extracts a feature vector from a normalized Event using config-driven rules.
 
    Instantiate once, then call extract() for each event in the pipeline.
    All thresholds and keyword lists are loaded from config.yaml at init time.
    """
    
    def __init__(self, config: dict):
        """
        Args:
            config: Full config dict loaded from config.yaml in main.py.
                    Uses config["features"] and config["rules"] sections.
        """
        feat_cfg   = config["features"]
        rules_cfg  = config["rules"]
        obfusc_cfg = rules_cfg["obfuscation"]

        # Length band thresholds
        self.len_short  = feat_cfg["length"]["short"]   # 100
        self.len_medium = feat_cfg["length"]["medium"]  # 300
        self.len_long   = feat_cfg["length"]["long"]    # 600