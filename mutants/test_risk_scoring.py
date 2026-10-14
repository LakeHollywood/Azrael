"""Unit tests for the authorization-impact risk floor:

    if operation.affects_authz():
        risk_score = max(risk_score, 60)

Run with: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest test_risk_scoring.py
"""

import pytest

from risk_scoring import (
    AUTHZ_IMPACTING_OPERATIONS,
    Operation,
    apply_risk_floor,
)


# ---------------------------------------------------------------------------
# Operation.affects_authz()
# ---------------------------------------------------------------------------

class TestAffectsAuthz:
    def test_explicit_flag_true(self):
        op = Operation(name="something_custom", affects_authz_flag=True)
        assert op.affects_authz() is True

    def test_explicit_flag_false_non_authz_name(self):
        op = Operation(name="read_telemetry", affects_authz_flag=False)
        assert op.affects_authz() is False

    @pytest.mark.parametrize("name", sorted(AUTHZ_IMPACTING_OPERATIONS))
    def test_known_authz_operation_names_detected(self, name):
        op = Operation(name=name)
        assert op.affects_authz() is True

    def test_unknown_name_not_authz(self):
        assert Operation(name="sync_clock").affects_authz() is False

    def test_name_lookup_is_case_sensitive(self):
        # "Grant_Role" is NOT in the registry — documents current behavior.
        assert Operation(name="Grant_Role").affects_authz() is False

    def test_flag_overrides_registry(self):
        # Even a non-authz name counts when explicitly flagged.
        assert Operation(name="read_telemetry", affects_authz_flag=True).affects_authz() is True


# ---------------------------------------------------------------------------
# Risk floor application
# ---------------------------------------------------------------------------

AUTHZ_OP = lambda: Operation(name="grant_role")
NON_AUTHZ_OP = lambda: Operation(name="read_telemetry")


class TestRiskFloor:
    def test_low_score_bumped_to_floor_for_authz_op(self):
        assert apply_risk_floor(10, AUTHZ_OP()) == 60

    def test_score_just_below_floor_bumped(self):
        assert apply_risk_floor(59.999, AUTHZ_OP()) == 60

    def test_score_at_floor_unchanged(self):
        assert apply_risk_floor(60, AUTHZ_OP()) == 60

    def test_score_above_floor_never_lowered(self):
        # max() semantics: the floor raises, it never caps.
        assert apply_risk_floor(87, AUTHZ_OP()) == 87

    def test_zero_and_negative_scores_bumped(self):
        assert apply_risk_floor(0, AUTHZ_OP()) == 60
        assert apply_risk_floor(-5, AUTHZ_OP()) == 60

    def test_non_authz_op_leaves_score_untouched(self):
        assert apply_risk_floor(10, NON_AUTHZ_OP()) == 10
        assert apply_risk_floor(95, NON_AUTHZ_OP()) == 95
        assert apply_risk_floor(0, NON_AUTHZ_OP()) == 0

    def test_float_precision_preserved_above_floor(self):
        assert apply_risk_floor(62.5, AUTHZ_OP()) == 62.5

    def test_idempotent(self):
        once = apply_risk_floor(30, AUTHZ_OP())
        assert apply_risk_floor(once, AUTHZ_OP()) == once == 60

    def test_flagged_custom_op_gets_floor(self):
        op = Operation(name="weird_internal_call", affects_authz_flag=True)
        assert apply_risk_floor(42, op) == 60

    def test_all_registry_names_trigger_floor(self):
        for name in AUTHZ_IMPACTING_OPERATIONS:
            assert apply_risk_floor(5, Operation(name=name)) == 60
