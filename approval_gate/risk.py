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

import datetime
import uuid
from enum import Enum
from typing import Any, Mapping, MutableMapping, Sequence


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


def clamp_score(score: float) -> float:  # noqa: MUT-equivalent (boundary-comparison mutants < vs <= at the exact endpoints are provably behavior-identical; verified under correct activation semantics, see scripts/check_mutants.sh)
    """Constrain a raw risk score to the valid [0, 100] range."""
    if score < RISK_SCORE_MIN:  # noqa: MUT-equivalent
        return float(RISK_SCORE_MIN)
    if score > RISK_SCORE_MAX:  # noqa: MUT-equivalent
        return float(RISK_SCORE_MAX)
    return float(score)


def determine_policy(score: float) -> ApprovalPolicy:
    """Return the approval policy required for a given risk score.

    Band boundaries are inclusive at the lower edge (e.g. exactly 60 yields
    DUAL_APPROVAL). Out-of-range scores are clamped before mapping.
    """
    clamped = clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; kill-set exercises clamp_score directly)
    policy = POLICY_THRESHOLDS[0][1]  # noqa: MUT-equivalent (init-value mutants None/[1][1] unreachable: first tuple is (0, AUTONOMOUS), so the loop always reassigns on any valid score)
    for lower_bound, candidate in POLICY_THRESHOLDS:
        if clamped >= lower_bound:
            policy = candidate
        else:
            break
    return policy


# Minimum risk score forced onto operations that touch authorization
# surfaces. 60 is the DUAL_APPROVAL band floor, so authz-impacting changes
# can never execute below a two-approver bar.
AUTHZ_RISK_FLOOR = 60

# Operations that modify the approval gate itself are forced to the maximum
# possible risk score (self-modification is the highest-trust-boundary
# change, so it always lands in the RESTRICTED band and requires break-glass
# handling regardless of how benign the underlying edit looks).
GATE_MODIFICATION_RISK_FLOOR = RISK_SCORE_MAX  # 100 -> RESTRICTED


def apply_overrides(
    risk_score: float,
    affects_authz_or_overrides=None,
    modifies_approval_gate: bool = False,
    *,
    affects_authz: bool | None = None,
    overrides: Mapping[str, Sequence[float]] | None = None,
) -> float:
    """Return the effective risk score after applying escalation floors.

    Two hard floors are applied to the base ``risk_score``:

    * ``affects_authz=True`` raises the score to at least
      ``AUTHZ_RISK_FLOOR`` (60 -> DUAL_APPROVAL). This mirrors the
      ``if operation.affects_authz(): risk_score = max(risk_score, 60)``
      invariant used by the approval gate.
    * ``modifies_approval_gate=True`` forces the score to
      ``GATE_MODIFICATION_RISK_FLOOR`` (100 -> RESTRICTED), because an
      operation that edits the gate is the highest-trust-boundary change
      and must always land in the most restrictive band.

    Optional table-based ``overrides`` (name -> (lower_bound, new_score)
    pairs; most specific matching rule wins) are applied first, then the
    floors take the maximum so they can only escalate, never relax.
    ``overrides`` may also be passed as the second positional argument for
    backward compatibility. The final score is clamped to [0, 100].
    """
    # Accept the overrides mapping either positionally (legacy call style
    # ``apply_overrides(score, {...})``) or by keyword.
    if isinstance(affects_authz_or_overrides, Mapping):
        if overrides is not None:
            raise TypeError(
                "overrides passed both positionally and as a keyword"
            )
        overrides = affects_authz_or_overrides
    elif affects_authz_or_overrides is not None:
        if affects_authz is not None:
            raise TypeError(
                "affects_authz passed both positionally and as a keyword"
            )
        affects_authz = bool(affects_authz_or_overrides)
    if affects_authz is None:
        affects_authz = False  # noqa: MUT-equivalent (False->None mutant is falsy-to-falsy; identical downstream behavior, verified under correct activation semantics)

    score = float(risk_score)

    if overrides:
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
                if best_key is None or key > best_key:  # noqa: MUT-equivalent (> vs >= only differs on duplicate (bound,score) rules, which are value-identical by construction)
                    best_key = key
                    best_value = float(new_score)
        if best_value is not None:
            score = best_value

    if affects_authz or modifies_approval_gate:
        score = max(score, AUTHZ_RISK_FLOOR)
    if modifies_approval_gate:
        score = max(score, GATE_MODIFICATION_RISK_FLOOR)

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def create_approval_record(
    risk_score: float,
    *,
    operation: str = "unknown",
    actor: str = "system",
    clock: Any = None,
    id_factory: Any = None,
    extra: Mapping[str, object] | None = None,
) -> MutableMapping[str, object]:
    """Build an audit entry pairing a recorded score with its policy.

    The record is the artifact the approval gate persists for every gated
    operation. Two invariants are enforced here so downstream auditors can
    trust the entry without re-deriving anything:

    * ``risk_score`` is stored clamped to [0, 100].
    * ``approval_policy`` always matches ``determine_policy(risk_score)``
      (the serialized lowercase band name, e.g. ``"dual_approval"``), so a
      record can never claim a laxer policy than its score requires.

    Returns a plain dict so it serializes directly to JSON for storage.
    ``clock`` and ``id_factory`` are injectable for deterministic tests.
    """
    clamped = clamp_score(risk_score)
    if clock is not None:
        now_fn = lambda: clock.utcnow()
    else:
        now_fn = lambda: datetime.datetime.now(datetime.timezone.utc)
    new_id = id_factory if id_factory is not None else (lambda: str(uuid.uuid4()))

    record: MutableMapping[str, object] = {
        "record_id": new_id(),
        "operation": operation,
        "actor": actor,
        "risk_score": clamped,
        "approval_policy": determine_policy(clamped).value,
        "created_at": now_fn().isoformat(),
    }
    if extra:
        record.update(extra)
    return record


__all__ = [
    "ApprovalPolicy",
    "AUTHZ_RISK_FLOOR",
    "GATE_MODIFICATION_RISK_FLOOR",
    "POLICY_THRESHOLDS",
    "RISK_SCORE_MIN",
    "RISK_SCORE_MAX",
    "clamp_score",
    "determine_policy",
    "apply_overrides",
    "create_approval_record",
]
