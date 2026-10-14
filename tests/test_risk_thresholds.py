# tests/test_risk_thresholds.py

import pytest

from approval_gate.risk import (
    determine_policy,
    apply_overrides,
    ApprovalPolicy,
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
