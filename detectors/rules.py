"""
detectors/rules.py
──────────────────
Rule-based detection layer — the first and fastest layer in the pipeline.

Reads the named feature flags produced by features/extractor.py and applies
deterministic rules to produce a rule_score between 0.0 and 1.0.

Design principles:
  - Fast: no model loading, no computation — just flag checks
  - Transparent: every score comes with a human-readable reason
  - High precision: rules only fire on strong, explicit signals
  - Config-driven: all patterns live in config.yaml, not in this file

Rule scoring logic:
  - Each matched rule contributes a fixed weight to the score
  - Multiple rules can fire on the same event — scores are capped at 1.0
  - A reason string is built for every fired rule for use in alerts

Score reference:
  0.0        → no rules fired
  0.0 – 1.0  → partial matches (suspicious but not certain)
  1.0        → one or more high-confidence rules fired (strong signal)
"""

from dataclasses import dataclass, field
from loguru import logger

from features.extractor import EventFeatures


# ── Rule Result ───────────────────────────────────────────────────────────────

@dataclass
class RuleResult:
    """
    Output of the rules engine for a single event.

    Attributes:
        score   : Risk score between 0.0 and 1.0.
                  0.0 = no rules fired, 1.0 = high-confidence match.
        reasons : List of rule names that fired, used in alert output.
                  Empty if score is 0.0.
    """
    score   : float
    reasons : list[str] = field(default_factory=list)


# ── Rule weights ──────────────────────────────────────────────────────────────
# Each rule carries a weight representing how strongly it signals an attack.
# Weights are additive — multiple rules firing on the same event accumulate.
# Final score is capped at 1.0.
#
# Weight guide:
#   1.00 — near-certain attack signal on its own
#   0.70 — strong signal, likely attack
#   0.50 — moderate signal, suspicious but needs corroboration
#   0.30 — weak signal, contributes to combined score only

RULE_WEIGHTS = {
    "rule_keyword_hit"          : 1.00,  # known injection phrase in prompt
    "rule_dangerous_action"     : 1.00,  # dangerous pattern in agent action
    "rule_obfuscation_zwc"      : 0.70,  # zero-width char evasion detected
    "rule_obfuscation_base64"   : 0.70,  # base64 encoded payload detected
    "rule_instruction_density"  : 0.50,  # high imperative verb ratio
    "rule_agent_no_action"      : 0.30,  # agent event with suspicious prompt but no logged action
}


# ── Rules Engine ──────────────────────────────────────────────────────────────

class RulesDetector:
    """
    Applies deterministic rules to an event's feature vector.

    Instantiate once, call evaluate() for each event.
    No state is maintained between calls — each evaluation is independent.
    """

    def __init__(self, config: dict):
        """
        Args:
            config: Full config dict from config.yaml.
                    Uses config["rules"] for any config-driven rule logic.
        """
        self.config = config
        logger.debug("RulesDetector initialised")

    def evaluate(self, features: EventFeatures) -> RuleResult:
        """
        Evaluate all rules against a single event's features.

        Checks each rule in order, accumulates score and reasons,
        then caps the final score at 1.0.

        Args:
            features: EventFeatures produced by FeatureExtractor.extract()

        Returns:
            RuleResult with final score and list of fired rule names.
        """
        score   = 0.0
        reasons = []

        # ── Rule 1: Injection keyword hit ─────────────────────────────────────
        # A known injection phrase was found in the prompt.
        # This is the strongest signal — these phrases have no legitimate use.
        if features.keyword_hit == 1:
            score += RULE_WEIGHTS["rule_keyword_hit"]
            reasons.append("rule_keyword_hit")

        # ── Rule 2: Dangerous agent action ────────────────────────────────────
        # The agent attempted an action matching a known dangerous pattern.
        # Only fires for agent events — chat events always have action = None.
        if features.has_dangerous_action == 1:
            score += RULE_WEIGHTS["rule_dangerous_action"]
            reasons.append("rule_dangerous_action")

        # ── Rule 3: Zero-width character obfuscation ───────────────────────────
        # Invisible unicode characters detected in the prompt.
        # Strong evasion signal — no legitimate reason for these in a prompt.
        if features.has_zero_width_chars == 1:
            score += RULE_WEIGHTS["rule_obfuscation_zwc"]
            reasons.append("rule_obfuscation_zwc")

        # ── Rule 4: Base64 encoded content ────────────────────────────────────
        # A base64-encoded payload detected in the prompt.
        # Attackers encode instructions to bypass keyword scanners.
        if features.has_base64_content == 1:
            score += RULE_WEIGHTS["rule_obfuscation_base64"]
            reasons.append("rule_obfuscation_base64")

        # ── Rule 5: High instruction density ──────────────────────────────────
        # Prompt contains an unusually high ratio of imperative verbs.
        # Moderate signal — contributes to score but rarely fires alone
        # on a legitimate event.
        if features.instruction_density == 1:
            score += RULE_WEIGHTS["rule_instruction_density"]
            reasons.append("rule_instruction_density")

        # ── Rule 6: Agent event with suspicious prompt but no action logged ────
        # An agent event where the prompt looks suspicious but no action
        # was captured. May indicate a partially blocked or stealthy attempt.
        # Weak signal — only meaningful in combination with other rules.
        if (
            features.is_agent_event == 1
            and features.has_dangerous_action == 0
            and features.instruction_density == 1
        ):
            score += RULE_WEIGHTS["rule_agent_no_action"]
            reasons.append("rule_agent_no_action")

        # ── Cap score at 1.0 ──────────────────────────────────────────────────
        # Multiple rules can fire simultaneously — we cap to keep the
        # final score within the 0.0–1.0 range expected by scorer.py.
        score = min(score, 1.0)

        return RuleResult(score=round(score, 4), reasons=reasons)

    def evaluate_all(self, features_list: list[EventFeatures]) -> list[RuleResult]:
        """
        Evaluate rules for a list of events.

        Args:
            features_list: List of EventFeatures from FeatureExtractor.extract_all()

        Returns:
            List of RuleResult in the same order as input.
        """
        results = [self.evaluate(f) for f in features_list]

        fired   = sum(1 for r in results if r.score > 0.0)
        logger.info(f"Rules detection complete — {fired}/{len(results)} events flagged")
        return results