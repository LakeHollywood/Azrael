"""Risk-score-to-approval-policy mapping.

An operation's composite risk score (0-100) determines the minimum approval
bar required before it may execute:

    0..19   AUTONOMOUS       agent proceeds without human sign-off
    20..39  SINGLE_APPROVAL  one operator approval
    40..59  SENIOR_APPROVAL  one senior-operator approval
    60..79  DUAL_APPROVAL    two independent approvals (authz-impacting floor)
    80..100 RESTRICTED       denied by default; break-glass only

Scores outside 0-100 are clamped to the nearest end of the range.
"""

from __future__ import annotations

from enum import Enum
from typing import Mapping, Sequence


class ApprovalPolicy(Enum):
    """Minimum approval requirement for an operation."""

    AUTONOMOUS = "autonomous"
    SINGLE_APPROVAL = "single_approval"
    SENIOR_APPROVAL = "senior_approval"
    DUAL_APPROVAL = "dual_approval"
    RESTRICTED = "restricted"

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return self.value


# Inclusive lower bound of each policy band, in ascending order. A score is
# mapped to the band with the highest lower bound it reaches.
POLICY_THRESHOLDS: tuple[tuple[int, ApprovalPolicy], ...] = (
    (0, ApprovalPolicy.AUTONOMOUS),
    (20, ApprovalPolicy.SINGLE_APPROVAL),
    (40, ApprovalPolicy.SENIOR_APPROVAL),
    (60, ApprovalPolicy.DUAL_APPROVAL),
    (80, ApprovalPolicy.RESTRICTED),
)

RISK_SCORE_MIN = 0
RISK_SCORE_MAX = 100


def clamp_score(score: float) -> float:
    """Constrain a raw risk score to the valid [0, 100] range."""
    if score < RISK_SCORE_MIN:
        return float(RISK_SCORE_MIN)
    if score > RISK_SCORE_MAX:
        return float(RISK_SCORE_MAX)
    return float(score)


def determine_policy(score: float) -> ApprovalPolicy:
    """Return the approval policy required for a given risk score.

    Band boundaries are inclusive at the lower edge (e.g. exactly 60 yields
    DUAL_APPROVAL). Out-of-range scores are clamped before mapping.
    """
    clamped = clamp_score(score)
    policy = POLICY_THRESHOLDS[0][1]
    for lower_bound, candidate in POLICY_THRESHOLDS:
        if clamped >= lower_bound:
            policy = candidate
        else:
            break
    return policy


def apply_overrides(
    score: float,
    overrides: Mapping[str, Sequence[float]],
) -> float:
    """Apply named risk-score overrides to a base score.

    ``overrides`` maps override names to ``(lower_bound, new_score)`` pairs:
    any base score at or above ``lower_bound`` is replaced by ``new_score``.
    When several overrides match, the one with the highest lower bound wins
    (most specific rule); ties are broken by the higher resulting score.
    The final score is clamped to [0, 100].
    """
    best_key: tuple[float, float] | None = None
    best_value: float | None = None
    for name, rule in overrides.items():
        try:
            lower_bound, new_score = rule
        except (TypeError, ValueError):
            raise ValueError(
                f"override {name!r} must be a (lower_bound, new_score) pair"
            )
        if score >= lower_bound:
            key = (float(lower_bound), float(new_score))
            if best_key is None or key > best_key:
                best_key = key
                best_value = float(new_score)
    result = score if best_value is None else best_value
    return clamp_score(result)


__all__ = [
    "ApprovalPolicy",
    "POLICY_THRESHOLDS",
    "RISK_SCORE_MIN",
    "RISK_SCORE_MAX",
    "clamp_score",
    "determine_policy",
    "apply_overrides",
]
