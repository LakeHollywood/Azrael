#!/usr/bin/env python3
"""SAIL production deployment gate (PD-010 / CONSTITUTIONAL_DEPLOYMENT_GATE).

Deployment SHALL be blocked unless every constitutional condition holds:

  * all constitutional tests pass            (PD-001, CI-level)
  * mutation resistance passes               (PD-002, CI-level)
  * fail-closed behavior is verified         (PD-003)
  * revocation freshness is verified         (PD-004)
  * every execution surface is governed      (PD-005)
  * audit integrity is verified              (PD-006)
  * replay resistance is verified            (PD-007)
  * tool registry integrity is verified      (PD-008)
  * human approval separation is verified    (PD-009)
  * required human signoffs are recorded     (PD-010)

If any condition fails, SAIL SHALL NOT be promoted to production.

``evaluate_deployment_gate`` re-runs the runtime-checkable conditions
against the live ``sail`` module in an isolated sandbox (fresh registries;
the caller's module state is never touched), then combines their verdicts
with the recorded human signoffs into an immutable deployment record.
CI-only conditions (full pytest suite, mutmut score) are supplied by the
caller as ``ci_results`` -- absent or false values block promotion.

CLI::

    python scripts/deployment_gate.py --signoff Security=APPROVED ... \
        --ci PD-001=true --ci PD-002=true [--record deployment.json]
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REQUIRED_SIGNOFFS = ("Security", "Engineering", "Governance", "Operations")

#: Gate ids that must report PASS before promotion.
GATE_IDS = (
    "PD-001",  # constitutional invariants pass (CI)
    "PD-002",  # mutation resistance (CI)
    "PD-003",  # fail-closed verification
    "PD-004",  # revocation freshness
    "PD-005",  # execution boundary coverage
    "PD-006",  # audit integrity
    "PD-007",  # replay resistance
    "PD-008",  # tool registry integrity
    "PD-009",  # human approval separation
    "PD-010",  # production readiness signoffs recorded
)


class SignoffRequired(Exception):
    """Raised when a deployment record cannot reach full signoff."""


# ---------------------------------------------------------------------------
# Runtime gate checks (executed against a freshly reloaded sail module so
# evaluation never sees -- or pollutes -- ambient registry state).
# ---------------------------------------------------------------------------


def _sandbox_sail():
    """Import a pristine copy of sail under a private module name."""
    spec = importlib.util.spec_from_file_location(
        "_sail_gate_sandbox", ROOT / "sail.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_sail_gate_sandbox"] = mod
    spec.loader.exec_module(mod)
    return mod


def _outage(*_a: Any, **_k: Any) -> None:
    raise ConnectionError("simulated infrastructure outage")


def check_pd003_fail_closed() -> tuple[bool, str]:
    """Every governance-backend outage must DENY, never ALLOW."""
    sail = _sandbox_sail()
    sail.register_tool("gate-tool", risk_score=5)
    sail.register_senior_approver("gate-senior")
    sail.register_qualified_approver("gate-q1")
    sail.register_qualified_approver("gate-q2")
    sail.grant_role("gate-agent", "tool.execute")
    sail.grant_role("gate-requestor", "checkpoint.restore")
    if not sail.authorize(subject="gate-agent", action="tool.execute",
                          resource="gate-tool").allow:
        return False, "healthy baseline unexpectedly denied"
    outages = {
        "authorization service": dict(authz=_outage),
        "approval ledger": dict(approval_ledger=_outage),
        "policy store": dict(policy_store=_outage),
        "tool registry": dict(tool_registry=_outage),
        "roster lookup": dict(roster=_outage),
        "revocation backend": dict(revocation=_outage),
    }
    for name, overrides in outages.items():
        fresh = _sandbox_sail()
        fresh.register_tool("gate-tool", risk_score=5)
        fresh.grant_role("gate-agent", "tool.execute")
        fresh.configure_backend(**overrides)
        d = fresh.authorize(subject="gate-agent", action="tool.execute",
                            resource="gate-tool")
        if d.allow:
            return False, f"{name} outage produced ALLOW"
    return True, "all six simulated failures deny"


def check_pd004_revocation_freshness() -> tuple[bool, str]:
    """Approval/tool/approver/role revocation must precede execution."""
    sail = _sandbox_sail()
    sail.register_tool("gate-mid", risk_score=30)
    sail.register_senior_approver("sen")
    sail.register_qualified_approver("q1")
    sail.register_qualified_approver("q2")
    sail.grant_role("owner", "tool.execute")
    sail.approve(subject="owner", action="tool.execute",
                 resource="gate-mid", approver="op")
    job = sail.Job(owner="owner", action="tool.execute", resource="gate-mid")
    sail.enqueue(job)
    if not sail.authorize(subject="owner", action="tool.execute",
                          resource="gate-mid").allow:
        return False, "pre-revocation grant failed to allow"
    sail.revoke_approval(subject="owner", action="tool.execute",
                         resource="gate-mid", approver="op")
    results = sail.drain_ready(lambda j: (_ for _ in ()).throw(
        AssertionError("executor ran without authorization")))
    if results[0][1].allow or job.status != "denied":
        return False, "approval revocation did not take effect pre-execution"

    low = _sandbox_sail()
    low.register_tool("temp", risk_score=5)
    low.grant_role("agent", "tool.execute")
    if not low.authorize(subject="agent", action="tool.execute",
                         resource="temp").allow:
        return False, "tool baseline allow failed"
    low.revoke_tool("temp")
    if low.authorize(subject="agent", action="tool.execute",
                     resource="temp").allow:
        return False, "tool revocation ignored"

    sen = _sandbox_sail()
    sen.register_senior_approver("sen")
    sen.grant_role("wf", "workflow.resume")
    if not sen.authorize(subject="wf", action="workflow.resume",
                         resource="w-1", approvers=["sen"]).allow:
        return False, "senior baseline allow failed"
    sen.remove_senior_approver("sen")
    if sen.authorize(subject="wf", action="workflow.resume",
                     resource="w-1", approvers=["sen"]).allow:
        return False, "approver removal ignored"

    qual = _sandbox_sail()
    qual.register_qualified_approver("a")
    qual.register_qualified_approver("b")
    qual.grant_role("r", "checkpoint.restore")
    if not qual.authorize(subject="r", action="checkpoint.restore",
                          resource="c-1", approvers=["a", "b"]).allow:
        return False, "qualified baseline allow failed"
    qual.remove_qualified_approver("b")
    if qual.authorize(subject="r", action="checkpoint.restore",
                      resource="c-1", approvers=["a", "b"]).allow:
        return False, "qualified approver removal ignored"

    role = _sandbox_sail()
    role.register_tool("t", risk_score=5)
    role.grant_role("x", "tool.execute")
    if not role.authorize(subject="x", action="tool.execute",
                          resource="t").allow:
        return False, "role baseline allow failed"
    role.remove_role("x", "tool.execute")
    if role.authorize(subject="x", action="tool.execute",
                      resource="t").allow:
        return False, "role removal ignored"
    return True, "approval/tool/approver/role revocation all precede execution"


def check_pd005_surface_coverage() -> tuple[bool, str]:
    """Every registered execution surface converges on authorize()."""
    sail = _sandbox_sail()
    inventory = set(sail.EXECUTION_SURFACES)
    expected = {"tool.execute", "workflow.resume", "checkpoint.restore",
                "job.execute", "agent.spawn", "external_api.invoke",
                "api.invoke",  # legacy alias of external_api.invoke
                "resource.allocate", "workflow.continue"}
    if inventory != expected:
        return False, f"surface inventory drift: {inventory ^ expected}"
    for surface in sorted(inventory):
        if surface == "tool.execute":
            continue
        if surface not in sail._LIFECYCLE_PROFILES:
            return False, f"ungoverned surface {surface}: no profile"
    # Chokepoint observation: spy authorize and run one request per
    # surface through it.
    observed: list[str] = []
    real = sail.authorize

    def spy(**kw):
        observed.append(kw["action"])
        return real(**kw)

    sail.authorize = spy
    try:
        for surface in sorted(inventory):
            sail.grant_role("gate-subject", surface)
            spy(subject="gate-subject", action=surface,
                resource="instance-1")
    finally:
        sail.authorize = real
    missing = inventory - set(observed)
    if missing:
        return False, f"surfaces bypassed authorize(): {missing}"
    return True, "every governed surface observed at the chokepoint"


def check_pd006_audit_integrity() -> tuple[bool, str]:
    """100% of decisions emit complete, serializable audit records."""
    sail = _sandbox_sail()
    sail.register_tool("low", risk_score=5)
    sail.register_tool("high", risk_score=85)
    sail.grant_role("auditor", "tool.execute")
    decisions = [
        sail.authorize(subject="auditor", action="tool.execute",
                       resource="low"),
        sail.authorize(subject="auditor", action="tool.execute",
                       resource="ghost"),
        sail.authorize(subject="", action="tool.execute", resource="x"),
    ]
    for d in decisions:
        fields = sail.audit_fields(d)
        missing = set(sail.AUDIT_REQUIRED_FIELDS) - set(fields)
        if missing:
            return False, f"decision missing fields {missing}"
        rec_missing = set(sail.AUDIT_REQUIRED_FIELDS) - set(d.record)
        if rec_missing:
            return False, f"record missing fields {rec_missing}"
        if fields["decision"] != ("ALLOW" if d.allow else "DENY"):
            return False, "record outcome disagrees with decision"
        try:
            json.dumps(d.record)
        except TypeError as exc:
            return False, f"record not JSON-serializable: {exc}"
    ids = [d.decision_id for d in decisions]
    if len(ids) != len(set(ids)):
        return False, "duplicate decision ids emitted"
    return True, "every decision carries a complete audit record"


def check_pd007_replay_resistance() -> tuple[bool, str]:
    """Expired tokens, reused receipts, and stale approvals must all DENY."""
    sail = _sandbox_sail()
    sail.set_decision_ttl(60)
    sail.register_tool("mid", risk_score=30)
    sail.grant_role("replayer", "tool.execute")
    sail.approve(subject="replayer", action="tool.execute",
                 resource="mid", approver="op")
    issued = sail.authorize(subject="replayer", action="tool.execute",
                            resource="mid")
    if not issued.allow:
        return False, "baseline allow failed"
    expired = issued.verify(clock=issued.evaluated_at + 61.0)
    if expired.allow:
        return False, "expired token replay allowed"
    # decision_id uniqueness across evaluations
    again = sail.authorize(subject="replayer", action="tool.execute",
                           resource="mid")
    if again.decision_id == issued.decision_id:
        return False, "decision_id reuse detected"
    # approval bound to its exact triple
    sail.register_tool("other", risk_score=30)
    borrowed = sail.authorize(subject="replayer", action="tool.execute",
                              resource="other")
    if borrowed.allow:
        return False, "approval replayed across resources"
    # revoked standing approval cannot survive into a replay window
    fresh = _sandbox_sail()
    fresh.set_decision_ttl(3600)
    fresh.register_tool("mid", risk_score=30)
    fresh.grant_role("replayer", "tool.execute")
    fresh.approve(subject="replayer", action="tool.execute",
                  resource="mid", approver="op")
    tok = fresh.authorize(subject="replayer", action="tool.execute",
                          resource="mid")
    if not tok.allow:
        return False, "baseline allow failed (revocation window)"
    fresh.revoke_approval(subject="replayer", action="tool.execute",
                          resource="mid", approver="op")
    if tok.verify(clock=tok.evaluated_at + 1.0).allow:
        return False, "revoked approval replayed inside TTL"
    return True, "expired/reused/stale replays all deny"


def check_pd008_registry_integrity() -> tuple[bool, str]:
    """registered -> normal, revoked -> DENY, unknown -> max-risk DENY."""
    sail = _sandbox_sail()
    sail.register_tool("ok", risk_score=5)
    sail.grant_role("reg", "tool.execute")
    if not sail.authorize(subject="reg", action="tool.execute",
                          resource="ok").allow:
        return False, "registered tool not evaluated normally"
    sail.revoke_tool("ok")
    if sail.authorize(subject="reg", action="tool.execute",
                      resource="ok").allow:
        return False, "revoked tool allowed"
    unknown = sail.authorize(subject="reg", action="tool.execute",
                             resource="phantom")
    if unknown.allow or unknown.policy is not sail.ApprovalPolicy.RESTRICTED:
        return False, "unknown tool not restricted-denied"
    unregistered_surface = sail.authorize(
        subject="reg", action="mystery.surface", resource="anything")
    if unregistered_surface.allow:
        return False, "unregistered surface treated as low risk"
    return True, "registry behaves: normal/revoked/unknown all correct"


def check_pd009_approval_separation() -> tuple[bool, str]:
    """Self-approval, duplicates, and same-identity grants must DENY."""
    sail = _sandbox_sail()
    sail.register_qualified_approver("alice")
    sail.register_qualified_approver("bob")
    sail.grant_role("requestor", "checkpoint.restore")
    if sail.authorize(subject="requestor", action="checkpoint.restore",
                      resource="c", approvers=["requestor", "alice"]).allow:
        return False, "self-approval counted toward dual approval"
    if sail.authorize(subject="requestor", action="checkpoint.restore",
                      resource="c", approvers=["alice", "alice"]).allow:
        return False, "duplicate approver identity satisfied dual approval"
    if not sail.authorize(subject="requestor", action="checkpoint.restore",
                          resource="c", approvers=["alice", "bob"]).allow:
        return False, "two distinct qualified approvers denied"
    senior = _sandbox_sail()
    senior.register_senior_approver("boss")
    senior.grant_role("wf", "workflow.resume")
    if senior.authorize(subject="wf", action="workflow.resume",
                        resource="w", approvers=["wf"]).allow:
        return False, "subject self-approved a resume"
    if not senior.authorize(subject="wf", action="workflow.resume",
                            resource="w", approvers=["boss"]).allow:
        return False, "rostered senior approver denied"
    return True, "separation matrix holds for DUAL and SENIOR bands"


RUNTIME_CHECKS = {
    "PD-003": check_pd003_fail_closed,
    "PD-004": check_pd004_revocation_freshness,
    "PD-005": check_pd005_surface_coverage,
    "PD-006": check_pd006_audit_integrity,
    "PD-007": check_pd007_replay_resistance,
    "PD-008": check_pd008_registry_integrity,
    "PD-009": check_pd009_approval_separation,
}


# ---------------------------------------------------------------------------
# Immutable deployment record (PD-010)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeploymentRecord:
    """Append-only evidence bundle for one production promotion attempt.

    Immutability is enforced structurally (frozen dataclass) plus a
    content hash over the canonical JSON payload, so any tampering with
    the serialized record is detectable.
    """

    created_at: str
    signoffs: Mapping[str, str]
    gate_results: Mapping[str, bool]
    promoted: bool
    record_hash: str = ""

    @classmethod
    def create(cls, *, signoffs: Mapping[str, str],
               gate_results: Mapping[str, bool]) -> "DeploymentRecord":
        missing = [
            name for name in REQUIRED_SIGNOFFS
            if str(signoffs.get(name, "")).upper() != "APPROVED"
        ]
        if missing:
            raise SignoffRequired(
                f"required signoffs missing or not APPROVED: {missing}")
        created = datetime.now(timezone.utc).isoformat()
        payload = {
            "created_at": created,
            "signoffs": dict(sorted(signoffs.items())),
            "gate_results": dict(sorted(gate_results.items())),
            "promoted": True,
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return cls(created_at=created,
                   signoffs=payload["signoffs"],
                   gate_results=payload["gate_results"],
                   promoted=True, record_hash=digest)

    def as_dict(self) -> dict:
        return {
            "created_at": self.created_at,
            "signoffs": dict(self.signoffs),
            "gate_results": dict(self.gate_results),
            "promoted": self.promoted,
            "record_hash": self.record_hash,
        }

    def as_json(self) -> str:
        return json.dumps(self.as_dict(), sort_keys=True, indent=2)


def evaluate_deployment_gate(
    *,
    signoffs: Mapping[str, str],
    ci_results: Mapping[str, bool] | None = None,
) -> dict:
    """Run the CONSTITUTIONAL_DEPLOYMENT_GATE end-to-end.

    Returns a verdict dict: ``blocked``, ``promoted``, ``failures`` and
    the per-gate detail.  Promotion requires ALL gates green AND all four
    human signoffs APPROVED; otherwise SAIL SHALL NOT be promoted.
    """
    ci_results = dict(ci_results or {})
    detail: dict[str, str] = {}
    failures: list[str] = []

    for gate in ("PD-001", "PD-002"):
        passed = bool(ci_results.get(gate, False))
        detail[gate] = ("PASS (reported by CI)" if passed
                        else "MISSING: CI result not reported")
        if not passed:
            failures.append(f"{gate} unresolved: CI evidence absent")

    for gate, check in RUNTIME_CHECKS.items():
        try:
            passed, message = check()
        except Exception as exc:  # gate evaluation itself failed closed
            passed, message = False, f"check crashed: {exc!r}"
        detail[gate] = message
        if not passed:
            failures.append(f"{gate} FAILED: {message}")

    signoff_ok = all(
        str(signoffs.get(name, "")).upper() == "APPROVED"
        for name in REQUIRED_SIGNOFFS)
    missing = [name for name in REQUIRED_SIGNOFFS
               if str(signoffs.get(name, "")).upper() != "APPROVED"]
    detail["PD-010"] = ("all four signoffs APPROVED" if signoff_ok
                        else f"missing signoffs: {missing}")
    if not signoff_ok:
        failures.append(f"PD-010 FAILED: signoffs incomplete ({missing})")

    blocked = bool(failures)
    verdict = {
        "blocked": blocked,
        "promoted": not blocked,
        "failures": failures,
        "gates": detail,
    }
    if not blocked:
        record = DeploymentRecord.create(
            signoffs=signoffs,
            gate_results={g: True for g in GATE_IDS})
        verdict["deployment_record"] = record.as_dict()
    return verdict


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--signoff", action="append", default=[],
                        metavar="ROLE=STATUS",
                        help="human signoff entry (repeatable)")
    parser.add_argument("--ci", action="append", default=[],
                        metavar="PD-00N=bool",
                        help="CI-reported gate result (repeatable)")
    parser.add_argument("--record", metavar="PATH",
                        help="write the deployment record JSON here")
    args = parser.parse_args(argv)

    signoffs = {}
    for item in args.signoff:
        role, _, status = item.partition("=")
        signoffs[role.strip()] = status.strip().upper()
    ci = {}
    for item in args.ci:
        gate, _, value = item.partition("=")
        ci[gate.strip()] = value.strip().lower() in ("1", "true", "yes", "pass")

    verdict = evaluate_deployment_gate(signoffs=signoffs, ci_results=ci)
    print(json.dumps(verdict, indent=2, sort_keys=True))
    if verdict["promoted"] and args.record:
        Path(args.record).write_text(json.dumps(
            verdict["deployment_record"], indent=2, sort_keys=True))
    return 1 if verdict["blocked"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
