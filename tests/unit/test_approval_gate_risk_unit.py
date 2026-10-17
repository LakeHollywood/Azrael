"""Unit tests for approval_gate.risk (complement to tests/test_risk_thresholds.py).

Focus areas not covered by the threshold/override kill-set suite:
  * clamp_score edge cases and float normalization
  * create_approval_record structure, defaults, and injectable clock/id_factory
  * apply_overrides argument-plumbing errors and table-precedence details
"""

from __future__ import annotations

import datetime

import pytest

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


# ---------------------------------------------------------------------------
# clamp_score
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (-1000.0, 0.0),
        (-0.5, 0.0),
        (0, 0.0),
        (42, 42.0),
        (99.99, 99.99),
        (100, 100.0),
        (100.001, 100.0),
        (1e9, 100.0),
    ],
)
def test_clamp_score_boundaries(raw, expected):
    assert clamp_score(raw) == expected


def test_clamp_score_returns_float():
    result = clamp_score(50)
    assert isinstance(result, float)


def test_clamp_score_is_idempotent():
    once = clamp_score(-5)
    assert clamp_score(once) == once
    twice_up = clamp_score(123.4)
    assert clamp_score(twice_up) == twice_up


# ---------------------------------------------------------------------------
# determine_policy — exhaustive sweep + monotonicity
# ---------------------------------------------------------------------------


def test_determine_policy_full_integer_sweep():
    expected_by_band = {
        range(0, 20): ApprovalPolicy.AUTONOMOUS,
        range(20, 40): ApprovalPolicy.SINGLE_APPROVAL,
        range(40, 60): ApprovalPolicy.SENIOR_APPROVAL,
        range(60, 80): ApprovalPolicy.DUAL_APPROVAL,
        range(80, 101): ApprovalPolicy.RESTRICTED,
    }
    for score in range(0, 101):
        for band, policy in expected_by_band.items():
            if score in band:
                assert determine_policy(score) is policy, f"score={score}"
                break


def test_determine_policy_out_of_range_clamps():
    assert determine_policy(-17) is ApprovalPolicy.AUTONOMOUS
    assert determine_policy(1000) is ApprovalPolicy.RESTRICTED


def test_determine_policy_fractional_scores_use_lower_bound():
    # 19.9 has not reached the 20 lower bound -> still AUTONOMOUS
    assert determine_policy(19.9) is ApprovalPolicy.AUTONOMOUS
    assert determine_policy(20.0) is ApprovalPolicy.SINGLE_APPROVAL
    assert determine_policy(59.999) is ApprovalPolicy.SENIOR_APPROVAL
    assert determine_policy(60.0001) is ApprovalPolicy.DUAL_APPROVAL


def test_determine_policy_is_monotonic_nondecreasing():
    order = [policy for _, policy in POLICY_THRESHOLDS]
    rank = {policy: i for i, policy in enumerate(order)}
    previous_rank = -1
    for score in [i / 2 for i in range(0, 201)]:
        current_rank = rank[determine_policy(score)]
        assert current_rank >= previous_rank, f"non-monotonic at {score}"
        previous_rank = current_rank


def test_approval_policy_str_returns_value():
    assert str(ApprovalPolicy.DUAL_APPROVAL) == "dual_approval"


# ---------------------------------------------------------------------------
# apply_overrides — plumbing errors and precedence
# ---------------------------------------------------------------------------


def test_apply_overrides_rejects_double_specified_overrides():
    with pytest.raises(TypeError):
        apply_overrides(10, {"a": (0, 5)}, overrides={"b": (0, 6)})


def test_apply_overrides_rejects_double_specified_affects_authz():
    with pytest.raises(TypeError):
        apply_overrides(10, True, affects_authz=True)


def test_apply_overrides_rejects_malformed_override_rule():
    with pytest.raises(ValueError, match="must be a"):
        apply_overrides(10, {"bad": (1, 2, 3)})
    with pytest.raises(ValueError, match="must be a"):
        apply_overrides(10, {"bad": "not-a-pair"})


def test_apply_overrides_most_specific_rule_wins():
    # Both rules match score 70; the one with the higher lower bound wins.
    table = {"coarse": (0, 30), "specific": (60, 95)}
    assert apply_overrides(70, overrides=table) == 95.0


def test_apply_overrides_skips_rules_below_current_score():
    table = {"only_high": (80, 10)}
    # Score 10 never reaches the 80 lower bound -> rule does not fire.
    assert apply_overrides(10, overrides=table) == 10.0


def test_apply_overrides_floors_can_only_escalate():
    # An override that would *lower* the score below the authz floor is
    # pulled back up to the floor.
    table = {"downgrade": (0, 5)}
    assert apply_overrides(70, overrides=table, affects_authz=True) == float(
        AUTHZ_RISK_FLOOR
    )


def test_apply_overrides_gate_modification_forces_max():
    assert (
        apply_overrides(0, modifies_approval_gate=True)
        == GATE_MODIFICATION_RISK_FLOOR
    )
    assert determine_policy(
        apply_overrides(0, modifies_approval_gate=True)
    ) is ApprovalPolicy.RESTRICTED


def test_apply_overrides_positional_bool_means_affects_authz():
    assert apply_overrides(10, True) == float(AUTHZ_RISK_FLOOR)
    assert apply_overrides(10, False) == 10.0


def test_apply_overrides_keyword_affects_authz_equivalent_to_positional():
    assert apply_overrides(10, affects_authz=True) == apply_overrides(10, True)


def test_apply_overrides_result_always_within_valid_range():
    assert apply_overrides(-50, affects_authz=True) >= RISK_SCORE_MIN
    assert apply_overrides(500, overrides={"x": (0, 900)}) <= RISK_SCORE_MAX


# ---------------------------------------------------------------------------
# create_approval_record
# ---------------------------------------------------------------------------


class FrozenClock:
    """Minimal clock stub exposing utcnow()."""

    def __init__(self, when: datetime.datetime):
        self._when = when

    def utcnow(self) -> datetime.datetime:
        return self._when


def _make_record(**kwargs):
    kwargs.setdefault("clock", FrozenClock(datetime.datetime(2026, 10, 18)))
    kwargs.setdefault("id_factory", lambda: "fixed-id")
    return create_approval_record(**kwargs)


def test_record_has_required_fields_and_defaults():
    record = _make_record(risk_score=65)
    assert set(record) >= {
        "record_id",
        "operation",
        "actor",
        "risk_score",
        "approval_policy",
        "created_at",
    }
    assert record["record_id"] == "fixed-id"
    assert record["operation"] == "unknown"
    assert record["actor"] == "system"
    assert record["risk_score"] == 65.0
    assert record["approval_policy"] == "dual_approval"
    assert record["created_at"] == "2026-10-18T00:00:00"


def test_record_policy_matches_determine_policy_invariant():
    for score in (-10, 0, 19, 20, 45, 60, 80, 100, 250):
        record = _make_record(risk_score=score)
        assert record["approval_policy"] == determine_policy(score).value
        assert RISK_SCORE_MIN <= record["risk_score"] <= RISK_SCORE_MAX


def test_record_extra_fields_are_merged():
    record = _make_record(risk_score=10, extra={"ticket": "OPS-1", "tags": ["a"]})
    assert record["ticket"] == "OPS-1"
    assert record["tags"] == ["a"]


def test_record_is_json_serializable_plain_dict():
    import json

    record = _make_record(risk_score=33, operation="deploy", actor="alice")
    assert isinstance(record, dict)
    json.dumps(record)  # must not raise


def test_record_without_clock_produces_tz_aware_iso_timestamp():
    record = create_approval_record(risk_score=50, id_factory=lambda: "x")
    parsed = datetime.datetime.fromisoformat(record["created_at"])
    assert parsed.tzinfo is not None


def test_record_default_id_factory_produces_distinct_uuids():
    a = create_approval_record(risk_score=5)
    b = create_approval_record(risk_score=5)
    assert a["record_id"] != b["record_id"]
    import uuid

    uuid.UUID(a["record_id"])  # valid UUID string
