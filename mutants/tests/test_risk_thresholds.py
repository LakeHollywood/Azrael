# tests/test_risk_thresholds.py

import datetime
import pytest
from hypothesis import given, strategies as st

from approval_gate.risk import (
    AUTHZ_RISK_FLOOR,
    GATE_MODIFICATION_RISK_FLOOR,
    POLICY_THRESHOLDS,
    RISK_SCORE_MAX,
    RISK_SCORE_MIN,
    ApprovalPolicy,
    apply_overrides,
    clamp_score,
    create_approval_record,
    determine_policy,
)


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, ApprovalPolicy.AUTONOMOUS),
        (19, ApprovalPolicy.AUTONOMOUS),

        (20, ApprovalPolicy.SINGLE_APPROVAL),
        (39, ApprovalPolicy.SINGLE_APPROVAL),

        (40, ApprovalPolicy.SENIOR_APPROVAL),
        (59, ApprovalPolicy.SENIOR_APPROVAL),

        (60, ApprovalPolicy.DUAL_APPROVAL),
        (79, ApprovalPolicy.DUAL_APPROVAL),

        (80, ApprovalPolicy.RESTRICTED),
        (100, ApprovalPolicy.RESTRICTED),
    ],
)
def test_policy_thresholds(score, expected):
    assert determine_policy(score) == expected


def test_all_threshold_boundaries():
    assert determine_policy(19) == ApprovalPolicy.AUTONOMOUS
    assert determine_policy(20) == ApprovalPolicy.SINGLE_APPROVAL

    assert determine_policy(39) == ApprovalPolicy.SINGLE_APPROVAL
    assert determine_policy(40) == ApprovalPolicy.SENIOR_APPROVAL

    assert determine_policy(59) == ApprovalPolicy.SENIOR_APPROVAL
    assert determine_policy(60) == ApprovalPolicy.DUAL_APPROVAL

    assert determine_policy(79) == ApprovalPolicy.DUAL_APPROVAL
    assert determine_policy(80) == ApprovalPolicy.RESTRICTED


# ---------------------------------------------------------------------------
# Supplementary coverage: boundaries between bands, clamping, overrides.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        # Just below each upper band edge stays in the lower band...
        (19.999, ApprovalPolicy.AUTONOMOUS),
        (39.999, ApprovalPolicy.SINGLE_APPROVAL),
        (59.999, ApprovalPolicy.SENIOR_APPROVAL),
        (79.999, ApprovalPolicy.DUAL_APPROVAL),
        # ...and exactly on the edge escalates.
        (20.0, ApprovalPolicy.SINGLE_APPROVAL),
        (40.0, ApprovalPolicy.SENIOR_APPROVAL),
        (60.0, ApprovalPolicy.DUAL_APPROVAL),
        (80.0, ApprovalPolicy.RESTRICTED),
    ],
)
def test_band_boundaries_inclusive_at_lower_edge(score, expected):
    assert determine_policy(score) == expected


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (-100, ApprovalPolicy.AUTONOMOUS),
        (-0.5, ApprovalPolicy.AUTONOMOUS),
        (100.5, ApprovalPolicy.RESTRICTED),
        (5000, ApprovalPolicy.RESTRICTED),
    ],
)
def test_out_of_range_scores_are_clamped(score, expected):
    assert determine_policy(score) == expected


def test_every_integer_score_maps_to_a_policy():
    """No gaps: all 101 integer scores map to exactly one of five policies."""
    mapped = {determine_policy(s) for s in range(0, 101)}
    assert mapped == set(ApprovalPolicy)


def test_policy_is_monotonic_increasing_with_score():
    """Higher risk never yields a less strict policy."""
    order = list(ApprovalPolicy)  # declared least -> most strict
    rank = {p: i for i, p in enumerate(order)}
    prev = rank[determine_policy(0)]
    for score in range(1, 101):
        cur = rank[determine_policy(score)]
        assert cur >= prev, f"policy regressed at score {score}"
        prev = cur


def test_apply_overrides_empty_mapping_is_identity():
    assert apply_overrides(42, {}) == 42


def test_apply_overrides_escalates_authz_impacting_floor():
    # Mirrors the authz floor rule: ops that affect authorization are
    # pulled up to at least DUAL_APPROVAL territory (score 60).
    overrides = {"authz_floor": (60, 85)}
    assert apply_overrides(55, overrides) == 55  # below trigger: untouched
    assert apply_overrides(70, overrides) == 85  # triggered: escalated
    assert determine_policy(apply_overrides(70, overrides)) is \
        ApprovalPolicy.RESTRICTED


def test_apply_overrides_most_specific_rule_wins():
    overrides = {
        "moderate": (50, 65),
        "severe": (75, 95),
    }
    assert apply_overrides(60, overrides) == 65   # only 'moderate' matches
    assert apply_overrides(80, overrides) == 95   # both match, higher bound wins


def test_apply_overrides_result_is_clamped():
    assert apply_overrides(90, {"bad_rule": (80, 250)}) == 100
    assert apply_overrides(90, {"bad_rule": (80, -20)}) == 0


def test_apply_overrides_rejects_malformed_rule():
    with pytest.raises(ValueError, match="must be a .* pair"):
        apply_overrides(50, {"broken": (10, 20, 30)})


def test_authz_operations_are_forced_to_dual_approval():
    score = apply_overrides(
        risk_score=15,
        affects_authz=True,
        modifies_approval_gate=False,
    )

    assert score >= 60
    assert determine_policy(score) == ApprovalPolicy.DUAL_APPROVAL


def test_non_authz_operations_keep_their_base_score():
    score = apply_overrides(
        risk_score=15,
        affects_authz=False,
        modifies_approval_gate=False,
    )
    assert score == 15
    assert determine_policy(score) == ApprovalPolicy.AUTONOMOUS


def test_high_base_score_is_not_relaxed_by_authz_floor():
    # The floor only escalates: max(87, 60) stays 87 -> RESTRICTED.
    score = apply_overrides(risk_score=87, affects_authz=True)
    assert score == 87
    assert determine_policy(score) == ApprovalPolicy.RESTRICTED


def test_gate_modification_is_escalated_past_the_authz_floor():
    score = apply_overrides(
        risk_score=15,
        affects_authz=False,
        modifies_approval_gate=True,
    )
    assert score >= 80
    assert determine_policy(score) == ApprovalPolicy.RESTRICTED


def test_authz_floor_applies_after_table_overrides():
    # A relaxation-style table override cannot drop an authz op below 60.
    overrides = {"discount": (10, 25)}
    score = apply_overrides(
        risk_score=30,
        affects_authz=True,
        overrides=overrides,
    )
    assert score == 60
    assert determine_policy(score) == ApprovalPolicy.DUAL_APPROVAL


@pytest.mark.parametrize("base", list(range(0, 60)))
def test_every_sub_floor_base_escalates_to_dual_approval(base):
    score = apply_overrides(risk_score=base, affects_authz=True)
    assert score == 60
    assert determine_policy(score) == ApprovalPolicy.DUAL_APPROVAL


def test_modifying_approval_gate_forces_maximum_risk():
    score = apply_overrides(
        risk_score=0,
        affects_authz=False,
        modifies_approval_gate=True,
    )

    assert score == 100
    assert determine_policy(score) == ApprovalPolicy.RESTRICTED


def test_gate_modification_forces_maximum_risk_from_high_base():
    # The floor is a hard force-to-max, not a band bump: even a base that
    # already sits in RESTRICTED lands on exactly 100.
    score = apply_overrides(
        risk_score=83,
        affects_authz=True,
        modifies_approval_gate=True,
    )
    assert score == 100
    assert determine_policy(score) == ApprovalPolicy.RESTRICTED


def test_gate_modification_ignores_relaxing_table_overrides():
    overrides = {"benign_edit": (0, 5)}
    score = apply_overrides(
        risk_score=10,
        affects_authz=False,
        modifies_approval_gate=True,
        overrides=overrides,
    )
    assert score == 100
    assert determine_policy(score) == ApprovalPolicy.RESTRICTED


@pytest.mark.parametrize("base", list(range(0, 100)))
def test_every_base_with_gate_modification_is_restricted(base):
    score = apply_overrides(
        risk_score=base,
        affects_authz=False,
        modifies_approval_gate=True,
    )
    assert score == 100
    assert determine_policy(score) == ApprovalPolicy.RESTRICTED


def test_approval_gate_override_wins_over_authz_override():
    score = apply_overrides(
        risk_score=70,
        affects_authz=True,
        modifies_approval_gate=True,
    )

    assert score == 100


# ---------------------------------------------------------------------------
# create_approval_record: audit entries must always pair a recorded score
# with the policy its threshold band requires.
# ---------------------------------------------------------------------------

from approval_gate.risk import create_approval_record  # noqa: E402


def test_policy_recorded_matches_threshold():
    recorded_score = 60

    entry = create_approval_record(
        risk_score=recorded_score,
    )

    assert entry["risk_score"] == 60
    assert entry["approval_policy"] == "dual_approval"


@pytest.mark.parametrize("score", list(range(0, 101)))
def test_recorded_policy_always_matches_determine_policy(score):
    entry = create_approval_record(risk_score=score)
    assert entry["risk_score"] == float(score)
    assert entry["approval_policy"] == determine_policy(score).value


def test_record_serializes_policy_as_lowercase_band_name():
    for expected in ("autonomous", "single_approval", "senior_approval",
                     "dual_approval", "restricted"):
        entry = create_approval_record(risk_score={"autonomous": 5,
                                                   "single_approval": 25,
                                                   "senior_approval": 45,
                                                   "dual_approval": 70,
                                                   "restricted": 95}[expected])
        assert entry["approval_policy"] == expected


def test_record_clamps_out_of_range_scores():
    low = create_approval_record(risk_score=-10)
    assert low["risk_score"] == 0
    assert low["approval_policy"] == "autonomous"

    high = create_approval_record(risk_score=5000)
    assert high["risk_score"] == 100
    assert high["approval_policy"] == "restricted"


def test_record_authz_floor_end_to_end():
    """apply_overrides authz floor -> record must show dual_approval."""
    score = apply_overrides(risk_score=15, affects_authz=True,
                            modifies_approval_gate=False)
    entry = create_approval_record(risk_score=score)
    assert entry["risk_score"] >= 60
    assert entry["approval_policy"] == "dual_approval"


def test_record_gate_modification_end_to_end():
    score = apply_overrides(risk_score=0, affects_authz=False,
                            modifies_approval_gate=True)
    entry = create_approval_record(risk_score=score)
    assert entry["risk_score"] == 100
    assert entry["approval_policy"] == "restricted"


def test_record_metadata_fields():
    entry = create_approval_record(
        risk_score=42,
        operation="rotate_signing_key",
        actor="agent-7",
        id_factory=lambda: "rec-001",
        extra={"ticket": "OPS-123"},
    )
    assert entry["record_id"] == "rec-001"
    assert entry["operation"] == "rotate_signing_key"
    assert entry["actor"] == "agent-7"
    assert entry["ticket"] == "OPS-123"
    # created_at is ISO-8601 parseable
    datetime.datetime.fromisoformat(str(entry["created_at"]))


def test_record_ids_unique_by_default():
    ids = {create_approval_record(risk_score=1)["record_id"] for _ in range(50)}
    assert len(ids) == 50


# ---------------------------------------------------------------------------
# Mutation-testing kill-set + constitutional invariants
# ---------------------------------------------------------------------------
# These tests exist specifically to kill mutants that boundary examples alone
# let survive (threshold off-by-one, removed branches, policy swaps, dropped
# override floors, and override-ordering permutations). See pyproject.toml
# [tool.mutmut] and scripts/check_mutants.sh for the CI enforcement gate.


def test_score_20_requires_single_approval():
    assert determine_policy(20) == ApprovalPolicy.SINGLE_APPROVAL


def test_score_60_requires_dual_approval():
    assert determine_policy(60) == ApprovalPolicy.DUAL_APPROVAL


def test_dual_boundary():
    assert determine_policy(60) == ApprovalPolicy.DUAL_APPROVAL
    assert determine_policy(79) == ApprovalPolicy.DUAL_APPROVAL


def test_single_approval_band():
    for score in (20, 25, 30, 35, 39):
        assert determine_policy(score) == ApprovalPolicy.SINGLE_APPROVAL


def test_authz_floor_is_dual_approval():
    result = apply_overrides(
        risk_score=0,
        affects_authz=True,
        modifies_approval_gate=False,
    )
    assert result >= 60


def test_approval_gate_change_always_max_risk():
    score = apply_overrides(
        risk_score=0,
        affects_authz=False,
        modifies_approval_gate=True,
    )
    assert score == 100


def test_gate_override_has_highest_precedence():
    # Kills ordering mutants: even if the authz floor were applied *after*
    # the gate floor, max() keeps the result pinned at 100.
    score = apply_overrides(
        risk_score=75,
        affects_authz=True,
        modifies_approval_gate=True,
    )
    assert score == 100


def test_policy_is_monotonic():
    """A higher risk score must never yield a less restrictive policy."""
    for score in range(100):
        current = determine_policy(score)
        nxt = determine_policy(score + 1)
        assert BAND_RANK[nxt] >= BAND_RANK[current]


def test_every_score_maps_to_policy():
    for score in range(101):
        policy = determine_policy(score)
        assert policy in {
            ApprovalPolicy.AUTONOMOUS,
            ApprovalPolicy.SINGLE_APPROVAL,
            ApprovalPolicy.SENIOR_APPROVAL,
            ApprovalPolicy.DUAL_APPROVAL,
            ApprovalPolicy.RESTRICTED,
        }


def test_no_authz_change_below_dual_approval():
    """Invariant 1: authz changes can never evaluate below DUAL_APPROVAL."""
    for score in range(101):
        adjusted = apply_overrides(
            risk_score=score,
            affects_authz=True,
            modifies_approval_gate=False,
        )
        assert adjusted >= 60
        assert determine_policy(adjusted) is ApprovalPolicy.DUAL_APPROVAL or \
            BAND_RANK[determine_policy(adjusted)] > BAND_RANK[ApprovalPolicy.DUAL_APPROVAL]


def test_no_gate_modification_below_restricted():
    """Invariant 2 (constitutional guardrail): gate modifications always
    evaluate to RESTRICTED (100), whatever the base score claims."""
    for score in range(101):
        adjusted = apply_overrides(
            risk_score=score,
            affects_authz=False,
            modifies_approval_gate=True,
        )
        assert adjusted == 100
        assert determine_policy(adjusted) is ApprovalPolicy.RESTRICTED


# Invariant 3 (monotonicity of the risk-policy mapping across 0-100) is
# covered by test_policy_is_monotonic above and the Hypothesis sweep below.

BAND_RANK = {p: i for i, p in enumerate([
    ApprovalPolicy.AUTONOMOUS,
    ApprovalPolicy.SINGLE_APPROVAL,
    ApprovalPolicy.SENIOR_APPROVAL,
    ApprovalPolicy.DUAL_APPROVAL,
    ApprovalPolicy.RESTRICTED,
])}


@given(st.integers(min_value=0, max_value=100))
def test_policy_is_monotonic_hypothesis(score):
    p1 = determine_policy(score)
    p2 = determine_policy(min(score + 1, 100))
    assert BAND_RANK[p2] >= BAND_RANK[p1]


@given(st.integers(min_value=-1000, max_value=1000))
def test_authz_floor_holds_for_any_raw_score(score):
    """Floors are total: any raw input with affects_authz lands >= 60."""
    adjusted = apply_overrides(
        risk_score=score,
        affects_authz=True,
        modifies_approval_gate=False,
    )
    assert adjusted >= 60


@given(st.integers(min_value=-1000, max_value=1000))
def test_gate_floor_holds_for_any_raw_score(score):
    adjusted = apply_overrides(
        risk_score=score,
        affects_authz=False,
        modifies_approval_gate=True,
    )
    assert adjusted == 100


# ---------------------------------------------------------------------------
# Surviving-mutant kill set (mutmut round 1)
# ---------------------------------------------------------------------------
# Each test below targets a specific mutation class that survived the first
# mutmut run: clamp boundary flips, table-constant mutations, override-rule
# strictness/tie-breaking, argument-validation paths, and record defaults.


def test_clamp_preserves_exact_endpoints():
    """Kills `score < MIN -> score <= MIN` and `score > MAX -> score >= MAX`:
    both endpoints must pass through unchanged, not be re-pinned."""
    assert clamp_score(0) == 0.0
    assert clamp_score(100) == 100.0
    assert clamp_score(-0.0001) == 0.0
    assert clamp_score(100.0001) == 100.0


@given(st.integers(min_value=RISK_SCORE_MIN, max_value=RISK_SCORE_MAX))
def test_clamp_is_identity_inside_range(score):
    assert clamp_score(score) == float(score)


def test_zero_maps_to_autonomous_not_default_slot():
    """Kills `policy = POLICY_THRESHOLDS[0][1] -> [1][1]/None`: if the loop
    never runs or starts from the wrong slot, score 0 stops being
    AUTONOMOUS."""
    assert determine_policy(0) is ApprovalPolicy.AUTONOMOUS


def test_threshold_table_is_the_canonical_five_bands():
    """Kills mutations of the POLICY_THRESHOLDS constants themselves."""
    assert POLICY_THRESHOLDS == (
        (0, ApprovalPolicy.AUTONOMOUS),
        (20, ApprovalPolicy.SINGLE_APPROVAL),
        (40, ApprovalPolicy.SENIOR_APPROVAL),
        (60, ApprovalPolicy.DUAL_APPROVAL),
        (80, ApprovalPolicy.RESTRICTED),
    )
    assert AUTHZ_RISK_FLOOR == 60
    assert GATE_MODIFICATION_RISK_FLOOR == 100


def test_override_lower_bound_is_inclusive():
    """Kills `if score >= lower_bound -> if score > lower_bound`: a rule at
    bound 30 must fire for exactly 30."""
    result = apply_overrides(30, overrides={"escalate": (30, 75)})
    assert result == 75


def test_duplicate_tied_rules_are_deterministic():
    """Kills `key > best_key -> key >= best_key` (and None mutations): with
    two rules sharing the same bound, the higher new_score wins regardless
    of iteration order."""
    a = {"r1": (20, 50), "r2": (20, 90)}
    b = {"r2": (20, 90), "r1": (20, 50)}
    assert apply_overrides(25, overrides=a) == 90
    assert apply_overrides(25, overrides=b) == 90


def test_conflicting_rules_most_specific_wins_both_orders():
    low_first = {"lo": (10, 45), "hi": (20, 85)}
    hi_first = {"hi": (20, 85), "lo": (10, 45)}
    assert apply_overrides(30, overrides=low_first) == 85
    assert apply_overrides(30, overrides=hi_first) == 85


def test_no_matching_rule_is_identity():
    assert apply_overrides(15, overrides={"high": (50, 90)}) == 15


def test_double_passed_overrides_raises():
    """Kills removal of the both-positional-and-keyword guard AND every
    mutation of its error message (message mutants are only killed when
    the assertion pins the text via ``match=``)."""
    with pytest.raises(
        TypeError, match=r"^overrides passed both positionally and as a keyword$"
    ):
        apply_overrides(10, {}, overrides={})


def test_double_passed_affects_authz_raises():
    """Same: exact-message match kills string mutants inside the raise."""
    with pytest.raises(
        TypeError,
        match=r"^affects_authz passed both positionally and as a keyword$",
    ):
        apply_overrides(10, True, affects_authz=True)


def test_positional_bool_flag_acts_as_affects_authz():
    """Kills `affects_authz = bool(x) -> bool(None)` on the legacy path."""
    assert apply_overrides(0, True) == 60
    assert apply_overrides(0, False) == 0


def test_none_floor_flags_do_not_escalate():
    """Kills `affects_authz = None` mutants: falsy flags must leave the
    base score untouched."""
    assert apply_overrides(
        risk_score=10, affects_authz=None, modifies_approval_gate=None
    ) == 10


def test_record_defaults_are_stable_strings():
    """Kills default-value string mutations ("XXunknownXX", "UNKNOWN", ...)."""
    entry = create_approval_record(risk_score=5)
    assert entry["operation"] == "unknown"
    assert entry["actor"] == "system"


def test_record_clock_injection_used():
    """Kills `now_fn = None / lambda: None`: created_at must always be a
    real ISO timestamp from the injected clock."""
    fixed = datetime.datetime(2026, 10, 15, 12, 0, 0, tzinfo=datetime.timezone.utc)

    class FakeClock:
        @staticmethod
        def utcnow():
            return fixed

    entry = create_approval_record(risk_score=5, clock=FakeClock())
    assert entry["created_at"] == fixed.isoformat()
    # parseable by every consumer even without injection
    parsed = datetime.datetime.fromisoformat(str(entry["created_at"]))
    assert parsed.tzinfo is not None  # kills datetime.now(None) mutant


# ---------------------------------------------------------------------------
# Third-round mutation kills (survivors from mutmut run #3)
# ---------------------------------------------------------------------------

def test_clamp_preserves_boundary_values_exactly():
    """Kills `score < MIN -> score <= MIN` and `score > MAX -> score >= MAX`:
    the boundary values themselves must pass through as float(score), not be
    short-circuited by an inclusive comparison."""
    assert clamp_score(0) == 0
    assert clamp_score(100) == 100
    assert clamp_score(-0.0001) == 0
    assert clamp_score(100.0001) == 100


def test_determine_policy_never_returns_none_for_any_score():
    """Kills `policy = None` initial-value mutant: even if the loop were
    starved, every reachable score must yield a real ApprovalPolicy."""
    for score in (-50, -0.1, 0, 0.5, 19.999, 20, 55, 100, 1e9):
        assert determine_policy(score) is not None
        assert isinstance(determine_policy(score), ApprovalPolicy)


def test_determine_policy_default_is_the_least_restrictive_band():
    """Kills `policy = POLICY_THRESHOLDS[0][1] -> [1][1]`: the initial
    default must be AUTONOMOUS, never SINGLE_APPROVAL or stricter."""
    assert determine_policy(0) == ApprovalPolicy.AUTONOMOUS
    assert determine_policy(-100) == ApprovalPolicy.AUTONOMOUS


def test_override_tie_break_is_stable_and_first_wins():
    """Kills `key > best_key -> key >= best_key`: with two rules that share
    both lower_bound and new_score, the FIRST-declared rule must win (strict
    improvement required to replace), keeping selection deterministic."""
    table = {"first": (10, 45), "second": (10, 45)}
    assert apply_overrides(50, overrides=table) == 45
    # reversed declaration order yields the same value (both identical) but
    # exercises the >= path; strict > keeps first-wins semantics stable
    reversed_table = {"second": (10, 45), "first": (10, 45)}
    assert apply_overrides(50, overrides=reversed_table) == 45


def test_record_without_clock_uses_aware_utc_now():
    """Kills `datetime.now(timezone.utc) -> datetime.now(None)`: a naive
    local-time timestamp would lack tzinfo and break ISO consumers."""
    entry = create_approval_record(risk_score=5)
    parsed = datetime.datetime.fromisoformat(str(entry["created_at"]))
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == datetime.timedelta(0)
