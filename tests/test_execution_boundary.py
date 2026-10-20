"""Execution-boundary invariant tests (EB-001 / EB-002 / EB-003).

Every governed operation -- tool invocation, workflow resume, checkpoint
restore, queued-job execution -- must converge on authorize() immediately
prior to execution.  Planning-time / historical approvals never satisfy
the execution-time requirement.
"""

import importlib

import pytest

from approval_gate.risk import ApprovalPolicy


@pytest.fixture(name="sail_mod")
def _fresh_sail():
    """Reload sail so module-level registries start empty per test."""
    mod = importlib.reload(importlib.import_module("sail"))
    yield mod
    importlib.reload(mod)


# ---------------------------------------------------------------------------
# EB-001: Workflow Resume Authorization
# ---------------------------------------------------------------------------

class TestEB001WorkflowResume:
    def _resume(self, sail, approvers=None):
        return sail.authorize(
            subject="wf-owner",
            action="workflow.resume",
            resource="wf-42",
            approvers=approvers,
        )

    def test_no_approval_present_denies(self, sail_mod):
        d = self._resume(sail_mod)
        assert not d.allow
        assert d.policy is ApprovalPolicy.SENIOR_APPROVAL

    def test_non_rostered_approver_denies(self, sail_mod):
        sail_mod.register_senior_approver("real-senior")
        d = self._resume(sail_mod, approvers=["not-a-senior"])
        assert not d.allow

    def test_one_rostered_senior_approval_allows(self, sail_mod):
        sail_mod.register_senior_approver("real-senior")
        d = self._resume(sail_mod, approvers=["real-senior"])
        assert d.allow

    def test_subject_cannot_self_approve(self, sail_mod):
        sail_mod.register_senior_approver("wf-owner")
        d = self._resume(sail_mod, approvers=["wf-owner"])
        assert not d.allow

    def test_approval_revoked_before_execution_denies(self, sail_mod):
        sail_mod.register_senior_approver("real-senior")
        sail_mod.approve(subject="wf-owner", action="workflow.resume",
                         resource="wf-42", approver="real-senior")
        assert self._resume(sail_mod).allow          # live grant -> ALLOW
        revoked = sail_mod.revoke_approval(
            subject="wf-owner", action="workflow.resume",
            resource="wf-42", approver="real-senior")
        assert revoked
        assert not self._resume(sail_mod).allow      # re-auth after revoke -> DENY

    def test_stale_decision_is_not_fresh(self, sail_mod):
        sail_mod.set_decision_ttl(60)
        d = sail_mod.authorize(subject="s", action="workflow.resume",
                               resource="w", clock=1_000.0)
        assert d.evaluated_at == 1_000.0
        assert not d.fresh  # "now" is far past the injected clock + TTL


# ---------------------------------------------------------------------------
# EB-002: Checkpoint Restore Authorization (risk 60 -> dual_approval)
# ---------------------------------------------------------------------------

class TestEB002CheckpointRestore:
    def _restore(self, sail, approvers):
        return sail.authorize(
            subject="requestor",
            action="checkpoint.restore",
            resource="ckpt-7",
            approvers=approvers,
        )

    def test_policy_is_dual_approval_at_risk_60(self, sail_mod):
        d = self._restore(sail_mod, [])
        assert d.policy is ApprovalPolicy.DUAL_APPROVAL
        assert d.risk_score == 60.0

    @pytest.mark.parametrize("approvers", [
        [],                       # 0 approvals
        ["alice"],                # 1 approval
        ["alice", "alice"],       # 2 identical approvers (collapse to one)
        ["bob", "carol"],         # 2 distinct *unqualified* approvers
    ])
    def test_denial_matrix(self, sail_mod, approvers):
        d = self._restore(sail_mod, approvers)
        assert not d.allow

    def test_two_distinct_qualified_approvers_allow(self, sail_mod):
        sail_mod.register_qualified_approver("alice")
        sail_mod.register_qualified_approver("dave")
        d = self._restore(sail_mod, ["alice", "dave"])
        assert d.allow

    def test_mixed_qualified_and_unqualified_denies(self, sail_mod):
        sail_mod.register_qualified_approver("alice")
        sail_mod.register_qualified_approver("dave")
        d = self._restore(sail_mod, ["alice", "mallory"])
        assert not d.allow

    def test_restore_never_relies_on_historical_authorization(self, sail_mod):
        # A checkpoint saved under yesterday's policy carries no authority:
        # with no live qualified grants, restore at execution time denies.
        sail_mod.register_qualified_approver("alice")
        sail_mod.register_qualified_approver("dave")
        sail_mod.approve(subject="requestor", action="checkpoint.restore",
                         resource="ckpt-7", approver="alice")
        sail_mod.approve(subject="requestor", action="checkpoint.restore",
                         resource="ckpt-7", approver="dave")
        assert self._restore(sail_mod, []).allow
        sail_mod.revoke_approval(subject="requestor", action="checkpoint.restore",
                                 resource="ckpt-7", approver="dave")
        assert not self._restore(sail_mod, []).allow


# ---------------------------------------------------------------------------
# EB-003: Tool Invocation Preservation
# ---------------------------------------------------------------------------

class TestEB003ToolInvocation:
    def _tool(self, sail, name, approvers=None):
        return sail.authorize(subject="agent-1", action="tool.execute",
                              resource=name, parameters={},
                              approvers=approvers)

    def test_registered_low_risk_autonomous_allow(self, sail_mod):
        sail_mod.register_tool("read_file", risk_score=5)
        d = self._tool(sail_mod, "read_file")
        assert d.allow and d.policy is ApprovalPolicy.AUTONOMOUS

    def test_registered_medium_risk_requires_approval(self, sail_mod):
        sail_mod.register_tool("write_db", risk_score=30)
        assert not self._tool(sail_mod, "write_db").allow
        assert self._tool(sail_mod, "write_db", ["op"]).allow

    def test_registered_high_risk_restricted(self, sail_mod):
        sail_mod.register_tool("delete_prod", risk_score=85)
        d = self._tool(sail_mod, "delete_prod")
        assert not d.allow and d.policy is ApprovalPolicy.RESTRICTED

    def test_unregistered_tool_denied(self, sail_mod):
        d = self._tool(sail_mod, "mystery_tool")
        assert not d.allow and d.policy is ApprovalPolicy.RESTRICTED

    def test_revoked_tool_denied(self, sail_mod):
        sail_mod.register_tool("temp_tool", risk_score=5)
        assert self._tool(sail_mod, "temp_tool").allow
        sail_mod.revoke_tool("temp_tool")
        d = self._tool(sail_mod, "temp_tool")
        assert not d.allow

    def test_authz_impacting_tool_floors_at_dual(self, sail_mod):
        sail_mod.register_tool("rotate_keys", risk_score=10, affects_authz=True)
        d = self._tool(sail_mod, "rotate_keys")
        assert d.risk_score >= 60
        assert d.policy is ApprovalPolicy.DUAL_APPROVAL
        assert not d.allow

    def test_gate_modification_tool_always_restricted(self, sail_mod):
        sail_mod.register_tool("edit_gate", risk_score=0,
                               modifies_approval_gate=True)
        d = self._tool(sail_mod, "edit_gate")
        assert d.risk_score == 100.0
        assert d.policy is ApprovalPolicy.RESTRICTED and not d.allow


# ---------------------------------------------------------------------------
# Combined constitutional rule: single chokepoint for every path
# ---------------------------------------------------------------------------

class TestExecutionBoundaryChokepoint:
    def test_queued_job_authorized_only_at_execution_time(self, sail_mod):
        # Enqueue happens hours before any approval exists; drain must
        # evaluate live state, not creation-time context.
        job = sail_mod.Job(owner="o", action="tool.execute",
                           resource="write_db")
        sail_mod.register_tool("write_db", risk_score=30)
        sail_mod.enqueue(job)
        results = sail_mod.drain_ready(lambda j: pytest.fail(
            "executor must not run without authorization"))
        assert not results[0][1].allow
        assert job.status == "denied"

    def test_missing_fields_fail_closed(self, sail_mod):
        for kw in ({"subject": "", "action": "a", "resource": "r"},
                  {"subject": "s", "action": "", "resource": "r"},
                  {"subject": "s", "action": "a", "resource": ""}):
            d = sail_mod.authorize(**kw)
            assert not d.allow

    def test_every_decision_carries_an_audit_record(self, sail_mod):
        sail_mod.register_tool("read_file", risk_score=5)
        d = sail_mod.authorize(subject="agent-1", action="tool.execute",
                               resource="read_file")
        assert d.record["operation"] == "tool.execute:read_file"
        assert d.record["approval_policy"] == d.policy.value
        denied = sail_mod.authorize(subject="agent-1", action="tool.execute",
                                    resource="ghost")
        assert not denied.allow
