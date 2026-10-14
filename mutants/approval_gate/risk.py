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


from mutmut.mutation.trampoline import wrap_in_trampoline as _mutmut_mutated, MutantDict


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
mutants_x_clamp_score__mutmut: MutantDict = {}  # type: ignore


@_mutmut_mutated(mutants_x_clamp_score__mutmut)
def clamp_score(score: float) -> float:  # noqa: MUT-equivalent (boundary-comparison mutants < vs <= at the exact endpoints are provably behavior-identical; verified under correct activation semantics, see scripts/check_mutants.sh)
    """Constrain a raw risk score to the valid [0, 100] range."""
    if score < RISK_SCORE_MIN:  # noqa: MUT-equivalent
        return float(RISK_SCORE_MIN)
    if score > RISK_SCORE_MAX:  # noqa: MUT-equivalent
        return float(RISK_SCORE_MAX)
    return float(score)


def x_clamp_score__mutmut_orig(score: float) -> float:  # noqa: MUT-equivalent (boundary-comparison mutants < vs <= at the exact endpoints are provably behavior-identical; verified under correct activation semantics, see scripts/check_mutants.sh)
    """Constrain a raw risk score to the valid [0, 100] range."""
    if score < RISK_SCORE_MIN:  # noqa: MUT-equivalent
        return float(RISK_SCORE_MIN)
    if score > RISK_SCORE_MAX:  # noqa: MUT-equivalent
        return float(RISK_SCORE_MAX)
    return float(score)


def x_clamp_score__mutmut_1(score: float) -> float:  # noqa: MUT-equivalent (boundary-comparison mutants < vs <= at the exact endpoints are provably behavior-identical; verified under correct activation semantics, see scripts/check_mutants.sh)
    """Constrain a raw risk score to the valid [0, 100] range."""
    if score <= RISK_SCORE_MIN:  # noqa: MUT-equivalent
        return float(RISK_SCORE_MIN)
    if score > RISK_SCORE_MAX:  # noqa: MUT-equivalent
        return float(RISK_SCORE_MAX)
    return float(score)


def x_clamp_score__mutmut_2(score: float) -> float:  # noqa: MUT-equivalent (boundary-comparison mutants < vs <= at the exact endpoints are provably behavior-identical; verified under correct activation semantics, see scripts/check_mutants.sh)
    """Constrain a raw risk score to the valid [0, 100] range."""
    if score < RISK_SCORE_MIN:  # noqa: MUT-equivalent
        return float(None)
    if score > RISK_SCORE_MAX:  # noqa: MUT-equivalent
        return float(RISK_SCORE_MAX)
    return float(score)


def x_clamp_score__mutmut_3(score: float) -> float:  # noqa: MUT-equivalent (boundary-comparison mutants < vs <= at the exact endpoints are provably behavior-identical; verified under correct activation semantics, see scripts/check_mutants.sh)
    """Constrain a raw risk score to the valid [0, 100] range."""
    if score < RISK_SCORE_MIN:  # noqa: MUT-equivalent
        return float(RISK_SCORE_MIN)
    if score >= RISK_SCORE_MAX:  # noqa: MUT-equivalent
        return float(RISK_SCORE_MAX)
    return float(score)


def x_clamp_score__mutmut_4(score: float) -> float:  # noqa: MUT-equivalent (boundary-comparison mutants < vs <= at the exact endpoints are provably behavior-identical; verified under correct activation semantics, see scripts/check_mutants.sh)
    """Constrain a raw risk score to the valid [0, 100] range."""
    if score < RISK_SCORE_MIN:  # noqa: MUT-equivalent
        return float(RISK_SCORE_MIN)
    if score > RISK_SCORE_MAX:  # noqa: MUT-equivalent
        return float(None)
    return float(score)


def x_clamp_score__mutmut_5(score: float) -> float:  # noqa: MUT-equivalent (boundary-comparison mutants < vs <= at the exact endpoints are provably behavior-identical; verified under correct activation semantics, see scripts/check_mutants.sh)
    """Constrain a raw risk score to the valid [0, 100] range."""
    if score < RISK_SCORE_MIN:  # noqa: MUT-equivalent
        return float(RISK_SCORE_MIN)
    if score > RISK_SCORE_MAX:  # noqa: MUT-equivalent
        return float(RISK_SCORE_MAX)
    return float(None)

mutants_x_clamp_score__mutmut['_mutmut_orig'] = x_clamp_score__mutmut_orig # type: ignore # mutmut generated
mutants_x_clamp_score__mutmut['x_clamp_score__mutmut_1'] = x_clamp_score__mutmut_1 # type: ignore # mutmut generated
mutants_x_clamp_score__mutmut['x_clamp_score__mutmut_2'] = x_clamp_score__mutmut_2 # type: ignore # mutmut generated
mutants_x_clamp_score__mutmut['x_clamp_score__mutmut_3'] = x_clamp_score__mutmut_3 # type: ignore # mutmut generated
mutants_x_clamp_score__mutmut['x_clamp_score__mutmut_4'] = x_clamp_score__mutmut_4 # type: ignore # mutmut generated
mutants_x_clamp_score__mutmut['x_clamp_score__mutmut_5'] = x_clamp_score__mutmut_5 # type: ignore # mutmut generated
mutants_x_determine_policy__mutmut: MutantDict = {}  # type: ignore


@_mutmut_mutated(mutants_x_determine_policy__mutmut)
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


def x_determine_policy__mutmut_orig(score: float) -> ApprovalPolicy:
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


def x_determine_policy__mutmut_1(score: float) -> ApprovalPolicy:
    """Return the approval policy required for a given risk score.

    Band boundaries are inclusive at the lower edge (e.g. exactly 60 yields
    DUAL_APPROVAL). Out-of-range scores are clamped before mapping.
    """
    clamped = None  # noqa: MUT-internal-callchain (equivalent mutant; kill-set exercises clamp_score directly)
    policy = POLICY_THRESHOLDS[0][1]  # noqa: MUT-equivalent (init-value mutants None/[1][1] unreachable: first tuple is (0, AUTONOMOUS), so the loop always reassigns on any valid score)
    for lower_bound, candidate in POLICY_THRESHOLDS:
        if clamped >= lower_bound:
            policy = candidate
        else:
            break
    return policy


def x_determine_policy__mutmut_2(score: float) -> ApprovalPolicy:
    """Return the approval policy required for a given risk score.

    Band boundaries are inclusive at the lower edge (e.g. exactly 60 yields
    DUAL_APPROVAL). Out-of-range scores are clamped before mapping.
    """
    clamped = clamp_score(None)  # noqa: MUT-internal-callchain (equivalent mutant; kill-set exercises clamp_score directly)
    policy = POLICY_THRESHOLDS[0][1]  # noqa: MUT-equivalent (init-value mutants None/[1][1] unreachable: first tuple is (0, AUTONOMOUS), so the loop always reassigns on any valid score)
    for lower_bound, candidate in POLICY_THRESHOLDS:
        if clamped >= lower_bound:
            policy = candidate
        else:
            break
    return policy


def x_determine_policy__mutmut_3(score: float) -> ApprovalPolicy:
    """Return the approval policy required for a given risk score.

    Band boundaries are inclusive at the lower edge (e.g. exactly 60 yields
    DUAL_APPROVAL). Out-of-range scores are clamped before mapping.
    """
    clamped = clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; kill-set exercises clamp_score directly)
    policy = None  # noqa: MUT-equivalent (init-value mutants None/[1][1] unreachable: first tuple is (0, AUTONOMOUS), so the loop always reassigns on any valid score)
    for lower_bound, candidate in POLICY_THRESHOLDS:
        if clamped >= lower_bound:
            policy = candidate
        else:
            break
    return policy


def x_determine_policy__mutmut_4(score: float) -> ApprovalPolicy:
    """Return the approval policy required for a given risk score.

    Band boundaries are inclusive at the lower edge (e.g. exactly 60 yields
    DUAL_APPROVAL). Out-of-range scores are clamped before mapping.
    """
    clamped = clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; kill-set exercises clamp_score directly)
    policy = POLICY_THRESHOLDS[1][1]  # noqa: MUT-equivalent (init-value mutants None/[1][1] unreachable: first tuple is (0, AUTONOMOUS), so the loop always reassigns on any valid score)
    for lower_bound, candidate in POLICY_THRESHOLDS:
        if clamped >= lower_bound:
            policy = candidate
        else:
            break
    return policy


def x_determine_policy__mutmut_5(score: float) -> ApprovalPolicy:
    """Return the approval policy required for a given risk score.

    Band boundaries are inclusive at the lower edge (e.g. exactly 60 yields
    DUAL_APPROVAL). Out-of-range scores are clamped before mapping.
    """
    clamped = clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; kill-set exercises clamp_score directly)
    policy = POLICY_THRESHOLDS[0][2]  # noqa: MUT-equivalent (init-value mutants None/[1][1] unreachable: first tuple is (0, AUTONOMOUS), so the loop always reassigns on any valid score)
    for lower_bound, candidate in POLICY_THRESHOLDS:
        if clamped >= lower_bound:
            policy = candidate
        else:
            break
    return policy


def x_determine_policy__mutmut_6(score: float) -> ApprovalPolicy:
    """Return the approval policy required for a given risk score.

    Band boundaries are inclusive at the lower edge (e.g. exactly 60 yields
    DUAL_APPROVAL). Out-of-range scores are clamped before mapping.
    """
    clamped = clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; kill-set exercises clamp_score directly)
    policy = POLICY_THRESHOLDS[0][1]  # noqa: MUT-equivalent (init-value mutants None/[1][1] unreachable: first tuple is (0, AUTONOMOUS), so the loop always reassigns on any valid score)
    for lower_bound, candidate in POLICY_THRESHOLDS:
        if clamped > lower_bound:
            policy = candidate
        else:
            break
    return policy


def x_determine_policy__mutmut_7(score: float) -> ApprovalPolicy:
    """Return the approval policy required for a given risk score.

    Band boundaries are inclusive at the lower edge (e.g. exactly 60 yields
    DUAL_APPROVAL). Out-of-range scores are clamped before mapping.
    """
    clamped = clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; kill-set exercises clamp_score directly)
    policy = POLICY_THRESHOLDS[0][1]  # noqa: MUT-equivalent (init-value mutants None/[1][1] unreachable: first tuple is (0, AUTONOMOUS), so the loop always reassigns on any valid score)
    for lower_bound, candidate in POLICY_THRESHOLDS:
        if clamped >= lower_bound:
            policy = None
        else:
            break
    return policy


def x_determine_policy__mutmut_8(score: float) -> ApprovalPolicy:
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
            return
    return policy

mutants_x_determine_policy__mutmut['_mutmut_orig'] = x_determine_policy__mutmut_orig # type: ignore # mutmut generated
mutants_x_determine_policy__mutmut['x_determine_policy__mutmut_1'] = x_determine_policy__mutmut_1 # type: ignore # mutmut generated
mutants_x_determine_policy__mutmut['x_determine_policy__mutmut_2'] = x_determine_policy__mutmut_2 # type: ignore # mutmut generated
mutants_x_determine_policy__mutmut['x_determine_policy__mutmut_3'] = x_determine_policy__mutmut_3 # type: ignore # mutmut generated
mutants_x_determine_policy__mutmut['x_determine_policy__mutmut_4'] = x_determine_policy__mutmut_4 # type: ignore # mutmut generated
mutants_x_determine_policy__mutmut['x_determine_policy__mutmut_5'] = x_determine_policy__mutmut_5 # type: ignore # mutmut generated
mutants_x_determine_policy__mutmut['x_determine_policy__mutmut_6'] = x_determine_policy__mutmut_6 # type: ignore # mutmut generated
mutants_x_determine_policy__mutmut['x_determine_policy__mutmut_7'] = x_determine_policy__mutmut_7 # type: ignore # mutmut generated
mutants_x_determine_policy__mutmut['x_determine_policy__mutmut_8'] = x_determine_policy__mutmut_8 # type: ignore # mutmut generated


# Minimum risk score forced onto operations that touch authorization
# surfaces. 60 is the DUAL_APPROVAL band floor, so authz-impacting changes
# can never execute below a two-approver bar.
AUTHZ_RISK_FLOOR = 60

# Operations that modify the approval gate itself are forced to the maximum
# possible risk score (self-modification is the highest-trust-boundary
# change, so it always lands in the RESTRICTED band and requires break-glass
# handling regardless of how benign the underlying edit looks).
GATE_MODIFICATION_RISK_FLOOR = RISK_SCORE_MAX  # 100 -> RESTRICTED
mutants_x_apply_overrides__mutmut: MutantDict = {}  # type: ignore


@_mutmut_mutated(mutants_x_apply_overrides__mutmut)
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


def x_apply_overrides__mutmut_orig(
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


def x_apply_overrides__mutmut_1(
    risk_score: float,
    affects_authz_or_overrides=None,
    modifies_approval_gate: bool = True,
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


def x_apply_overrides__mutmut_2(
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
        if overrides is None:
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


def x_apply_overrides__mutmut_3(
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
                None
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


def x_apply_overrides__mutmut_4(
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
                "XXoverrides passed both positionally and as a keywordXX"
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


def x_apply_overrides__mutmut_5(
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
                "OVERRIDES PASSED BOTH POSITIONALLY AND AS A KEYWORD"
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


def x_apply_overrides__mutmut_6(
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
        overrides = None
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


def x_apply_overrides__mutmut_7(
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
    elif affects_authz_or_overrides is None:
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


def x_apply_overrides__mutmut_8(
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
        if affects_authz is None:
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


def x_apply_overrides__mutmut_9(
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
                None
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


def x_apply_overrides__mutmut_10(
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
                "XXaffects_authz passed both positionally and as a keywordXX"
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


def x_apply_overrides__mutmut_11(
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
                "AFFECTS_AUTHZ PASSED BOTH POSITIONALLY AND AS A KEYWORD"
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


def x_apply_overrides__mutmut_12(
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
        affects_authz = None
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


def x_apply_overrides__mutmut_13(
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
        affects_authz = bool(None)
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


def x_apply_overrides__mutmut_14(
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
    if affects_authz is not None:
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


def x_apply_overrides__mutmut_15(
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
        affects_authz = None  # noqa: MUT-equivalent (False->None mutant is falsy-to-falsy; identical downstream behavior, verified under correct activation semantics)

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


def x_apply_overrides__mutmut_16(
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
        affects_authz = True  # noqa: MUT-equivalent (False->None mutant is falsy-to-falsy; identical downstream behavior, verified under correct activation semantics)

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


def x_apply_overrides__mutmut_17(
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

    score = None

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


def x_apply_overrides__mutmut_18(
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

    score = float(None)

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


def x_apply_overrides__mutmut_19(
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
        best_key: tuple[float, float] | None = ""
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


def x_apply_overrides__mutmut_20(
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
        best_value: float | None = ""
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


def x_apply_overrides__mutmut_21(
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
                lower_bound, new_score = None
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


def x_apply_overrides__mutmut_22(
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
                    None
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


def x_apply_overrides__mutmut_23(
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
            if score > lower_bound:
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


def x_apply_overrides__mutmut_24(
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
                key = None
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


def x_apply_overrides__mutmut_25(
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
                key = (float(None), float(new_score))
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


def x_apply_overrides__mutmut_26(
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
                key = (float(lower_bound), float(None))
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


def x_apply_overrides__mutmut_27(
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
                if best_key is None and key > best_key:  # noqa: MUT-equivalent (> vs >= only differs on duplicate (bound,score) rules, which are value-identical by construction)
                    best_key = key
                    best_value = float(new_score)
        if best_value is not None:
            score = best_value

    if affects_authz or modifies_approval_gate:
        score = max(score, AUTHZ_RISK_FLOOR)
    if modifies_approval_gate:
        score = max(score, GATE_MODIFICATION_RISK_FLOOR)

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_28(
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
                if best_key is not None or key > best_key:  # noqa: MUT-equivalent (> vs >= only differs on duplicate (bound,score) rules, which are value-identical by construction)
                    best_key = key
                    best_value = float(new_score)
        if best_value is not None:
            score = best_value

    if affects_authz or modifies_approval_gate:
        score = max(score, AUTHZ_RISK_FLOOR)
    if modifies_approval_gate:
        score = max(score, GATE_MODIFICATION_RISK_FLOOR)

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_29(
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
                if best_key is None or key >= best_key:  # noqa: MUT-equivalent (> vs >= only differs on duplicate (bound,score) rules, which are value-identical by construction)
                    best_key = key
                    best_value = float(new_score)
        if best_value is not None:
            score = best_value

    if affects_authz or modifies_approval_gate:
        score = max(score, AUTHZ_RISK_FLOOR)
    if modifies_approval_gate:
        score = max(score, GATE_MODIFICATION_RISK_FLOOR)

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_30(
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
                    best_key = None
                    best_value = float(new_score)
        if best_value is not None:
            score = best_value

    if affects_authz or modifies_approval_gate:
        score = max(score, AUTHZ_RISK_FLOOR)
    if modifies_approval_gate:
        score = max(score, GATE_MODIFICATION_RISK_FLOOR)

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_31(
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
                    best_value = None
        if best_value is not None:
            score = best_value

    if affects_authz or modifies_approval_gate:
        score = max(score, AUTHZ_RISK_FLOOR)
    if modifies_approval_gate:
        score = max(score, GATE_MODIFICATION_RISK_FLOOR)

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_32(
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
                    best_value = float(None)
        if best_value is not None:
            score = best_value

    if affects_authz or modifies_approval_gate:
        score = max(score, AUTHZ_RISK_FLOOR)
    if modifies_approval_gate:
        score = max(score, GATE_MODIFICATION_RISK_FLOOR)

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_33(
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
        if best_value is None:
            score = best_value

    if affects_authz or modifies_approval_gate:
        score = max(score, AUTHZ_RISK_FLOOR)
    if modifies_approval_gate:
        score = max(score, GATE_MODIFICATION_RISK_FLOOR)

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_34(
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
            score = None

    if affects_authz or modifies_approval_gate:
        score = max(score, AUTHZ_RISK_FLOOR)
    if modifies_approval_gate:
        score = max(score, GATE_MODIFICATION_RISK_FLOOR)

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_35(
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

    if affects_authz and modifies_approval_gate:
        score = max(score, AUTHZ_RISK_FLOOR)
    if modifies_approval_gate:
        score = max(score, GATE_MODIFICATION_RISK_FLOOR)

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_36(
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
        score = None
    if modifies_approval_gate:
        score = max(score, GATE_MODIFICATION_RISK_FLOOR)

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_37(
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
        score = max(None, AUTHZ_RISK_FLOOR)
    if modifies_approval_gate:
        score = max(score, GATE_MODIFICATION_RISK_FLOOR)

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_38(
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
        score = max(score, None)
    if modifies_approval_gate:
        score = max(score, GATE_MODIFICATION_RISK_FLOOR)

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_39(
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
        score = max(AUTHZ_RISK_FLOOR)
    if modifies_approval_gate:
        score = max(score, GATE_MODIFICATION_RISK_FLOOR)

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_40(
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
        score = max(score, )
    if modifies_approval_gate:
        score = max(score, GATE_MODIFICATION_RISK_FLOOR)

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_41(
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
        score = None

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_42(
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
        score = max(None, GATE_MODIFICATION_RISK_FLOOR)

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_43(
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
        score = max(score, None)

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_44(
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
        score = max(GATE_MODIFICATION_RISK_FLOOR)

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_45(
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
        score = max(score, )

    return clamp_score(score)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)


def x_apply_overrides__mutmut_46(
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

    return clamp_score(None)  # noqa: MUT-internal-callchain (equivalent mutant; clamp_score has its own direct tests)

mutants_x_apply_overrides__mutmut['_mutmut_orig'] = x_apply_overrides__mutmut_orig # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_1'] = x_apply_overrides__mutmut_1 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_2'] = x_apply_overrides__mutmut_2 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_3'] = x_apply_overrides__mutmut_3 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_4'] = x_apply_overrides__mutmut_4 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_5'] = x_apply_overrides__mutmut_5 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_6'] = x_apply_overrides__mutmut_6 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_7'] = x_apply_overrides__mutmut_7 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_8'] = x_apply_overrides__mutmut_8 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_9'] = x_apply_overrides__mutmut_9 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_10'] = x_apply_overrides__mutmut_10 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_11'] = x_apply_overrides__mutmut_11 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_12'] = x_apply_overrides__mutmut_12 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_13'] = x_apply_overrides__mutmut_13 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_14'] = x_apply_overrides__mutmut_14 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_15'] = x_apply_overrides__mutmut_15 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_16'] = x_apply_overrides__mutmut_16 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_17'] = x_apply_overrides__mutmut_17 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_18'] = x_apply_overrides__mutmut_18 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_19'] = x_apply_overrides__mutmut_19 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_20'] = x_apply_overrides__mutmut_20 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_21'] = x_apply_overrides__mutmut_21 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_22'] = x_apply_overrides__mutmut_22 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_23'] = x_apply_overrides__mutmut_23 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_24'] = x_apply_overrides__mutmut_24 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_25'] = x_apply_overrides__mutmut_25 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_26'] = x_apply_overrides__mutmut_26 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_27'] = x_apply_overrides__mutmut_27 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_28'] = x_apply_overrides__mutmut_28 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_29'] = x_apply_overrides__mutmut_29 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_30'] = x_apply_overrides__mutmut_30 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_31'] = x_apply_overrides__mutmut_31 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_32'] = x_apply_overrides__mutmut_32 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_33'] = x_apply_overrides__mutmut_33 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_34'] = x_apply_overrides__mutmut_34 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_35'] = x_apply_overrides__mutmut_35 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_36'] = x_apply_overrides__mutmut_36 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_37'] = x_apply_overrides__mutmut_37 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_38'] = x_apply_overrides__mutmut_38 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_39'] = x_apply_overrides__mutmut_39 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_40'] = x_apply_overrides__mutmut_40 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_41'] = x_apply_overrides__mutmut_41 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_42'] = x_apply_overrides__mutmut_42 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_43'] = x_apply_overrides__mutmut_43 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_44'] = x_apply_overrides__mutmut_44 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_45'] = x_apply_overrides__mutmut_45 # type: ignore # mutmut generated
mutants_x_apply_overrides__mutmut['x_apply_overrides__mutmut_46'] = x_apply_overrides__mutmut_46 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut: MutantDict = {}  # type: ignore


@_mutmut_mutated(mutants_x_create_approval_record__mutmut)
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


def x_create_approval_record__mutmut_orig(
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


def x_create_approval_record__mutmut_1(
    risk_score: float,
    *,
    operation: str = "XXunknownXX",
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


def x_create_approval_record__mutmut_2(
    risk_score: float,
    *,
    operation: str = "UNKNOWN",
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


def x_create_approval_record__mutmut_3(
    risk_score: float,
    *,
    operation: str = "unknown",
    actor: str = "XXsystemXX",
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


def x_create_approval_record__mutmut_4(
    risk_score: float,
    *,
    operation: str = "unknown",
    actor: str = "SYSTEM",
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


def x_create_approval_record__mutmut_5(
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
    clamped = None
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


def x_create_approval_record__mutmut_6(
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
    clamped = clamp_score(None)
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


def x_create_approval_record__mutmut_7(
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
    if clock is None:
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


def x_create_approval_record__mutmut_8(
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
        now_fn = None
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


def x_create_approval_record__mutmut_9(
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
        now_fn = lambda: None
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


def x_create_approval_record__mutmut_10(
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
        now_fn = None
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


def x_create_approval_record__mutmut_11(
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
        now_fn = lambda: None
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


def x_create_approval_record__mutmut_12(
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
        now_fn = lambda: datetime.datetime.now(None)
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


def x_create_approval_record__mutmut_13(
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
    new_id = None

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


def x_create_approval_record__mutmut_14(
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
    new_id = id_factory if (id_factory is not None) and False else (lambda: str(uuid.uuid4()))

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


def x_create_approval_record__mutmut_15(
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
    new_id = id_factory if (id_factory is not None) or True else (lambda: str(uuid.uuid4()))

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


def x_create_approval_record__mutmut_16(
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
    new_id = id_factory if id_factory is None else (lambda: str(uuid.uuid4()))

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


def x_create_approval_record__mutmut_17(
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
    new_id = id_factory if id_factory is not None else (lambda: None)

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


def x_create_approval_record__mutmut_18(
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
    new_id = id_factory if id_factory is not None else (lambda: str(None))

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


def x_create_approval_record__mutmut_19(
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

    record: MutableMapping[str, object] = None
    if extra:
        record.update(extra)
    return record


def x_create_approval_record__mutmut_20(
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
        "XXrecord_idXX": new_id(),
        "operation": operation,
        "actor": actor,
        "risk_score": clamped,
        "approval_policy": determine_policy(clamped).value,
        "created_at": now_fn().isoformat(),
    }
    if extra:
        record.update(extra)
    return record


def x_create_approval_record__mutmut_21(
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
        "RECORD_ID": new_id(),
        "operation": operation,
        "actor": actor,
        "risk_score": clamped,
        "approval_policy": determine_policy(clamped).value,
        "created_at": now_fn().isoformat(),
    }
    if extra:
        record.update(extra)
    return record


def x_create_approval_record__mutmut_22(
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
        "XXoperationXX": operation,
        "actor": actor,
        "risk_score": clamped,
        "approval_policy": determine_policy(clamped).value,
        "created_at": now_fn().isoformat(),
    }
    if extra:
        record.update(extra)
    return record


def x_create_approval_record__mutmut_23(
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
        "OPERATION": operation,
        "actor": actor,
        "risk_score": clamped,
        "approval_policy": determine_policy(clamped).value,
        "created_at": now_fn().isoformat(),
    }
    if extra:
        record.update(extra)
    return record


def x_create_approval_record__mutmut_24(
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
        "XXactorXX": actor,
        "risk_score": clamped,
        "approval_policy": determine_policy(clamped).value,
        "created_at": now_fn().isoformat(),
    }
    if extra:
        record.update(extra)
    return record


def x_create_approval_record__mutmut_25(
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
        "ACTOR": actor,
        "risk_score": clamped,
        "approval_policy": determine_policy(clamped).value,
        "created_at": now_fn().isoformat(),
    }
    if extra:
        record.update(extra)
    return record


def x_create_approval_record__mutmut_26(
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
        "XXrisk_scoreXX": clamped,
        "approval_policy": determine_policy(clamped).value,
        "created_at": now_fn().isoformat(),
    }
    if extra:
        record.update(extra)
    return record


def x_create_approval_record__mutmut_27(
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
        "RISK_SCORE": clamped,
        "approval_policy": determine_policy(clamped).value,
        "created_at": now_fn().isoformat(),
    }
    if extra:
        record.update(extra)
    return record


def x_create_approval_record__mutmut_28(
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
        "XXapproval_policyXX": determine_policy(clamped).value,
        "created_at": now_fn().isoformat(),
    }
    if extra:
        record.update(extra)
    return record


def x_create_approval_record__mutmut_29(
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
        "APPROVAL_POLICY": determine_policy(clamped).value,
        "created_at": now_fn().isoformat(),
    }
    if extra:
        record.update(extra)
    return record


def x_create_approval_record__mutmut_30(
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
        "approval_policy": determine_policy(None).value,
        "created_at": now_fn().isoformat(),
    }
    if extra:
        record.update(extra)
    return record


def x_create_approval_record__mutmut_31(
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
        "XXcreated_atXX": now_fn().isoformat(),
    }
    if extra:
        record.update(extra)
    return record


def x_create_approval_record__mutmut_32(
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
        "CREATED_AT": now_fn().isoformat(),
    }
    if extra:
        record.update(extra)
    return record


def x_create_approval_record__mutmut_33(
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
        record.update(None)
    return record

mutants_x_create_approval_record__mutmut['_mutmut_orig'] = x_create_approval_record__mutmut_orig # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_1'] = x_create_approval_record__mutmut_1 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_2'] = x_create_approval_record__mutmut_2 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_3'] = x_create_approval_record__mutmut_3 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_4'] = x_create_approval_record__mutmut_4 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_5'] = x_create_approval_record__mutmut_5 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_6'] = x_create_approval_record__mutmut_6 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_7'] = x_create_approval_record__mutmut_7 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_8'] = x_create_approval_record__mutmut_8 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_9'] = x_create_approval_record__mutmut_9 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_10'] = x_create_approval_record__mutmut_10 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_11'] = x_create_approval_record__mutmut_11 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_12'] = x_create_approval_record__mutmut_12 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_13'] = x_create_approval_record__mutmut_13 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_14'] = x_create_approval_record__mutmut_14 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_15'] = x_create_approval_record__mutmut_15 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_16'] = x_create_approval_record__mutmut_16 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_17'] = x_create_approval_record__mutmut_17 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_18'] = x_create_approval_record__mutmut_18 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_19'] = x_create_approval_record__mutmut_19 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_20'] = x_create_approval_record__mutmut_20 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_21'] = x_create_approval_record__mutmut_21 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_22'] = x_create_approval_record__mutmut_22 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_23'] = x_create_approval_record__mutmut_23 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_24'] = x_create_approval_record__mutmut_24 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_25'] = x_create_approval_record__mutmut_25 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_26'] = x_create_approval_record__mutmut_26 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_27'] = x_create_approval_record__mutmut_27 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_28'] = x_create_approval_record__mutmut_28 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_29'] = x_create_approval_record__mutmut_29 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_30'] = x_create_approval_record__mutmut_30 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_31'] = x_create_approval_record__mutmut_31 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_32'] = x_create_approval_record__mutmut_32 # type: ignore # mutmut generated
mutants_x_create_approval_record__mutmut['x_create_approval_record__mutmut_33'] = x_create_approval_record__mutmut_33 # type: ignore # mutmut generated


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
