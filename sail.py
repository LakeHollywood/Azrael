#!/usr/bin/env python3
"""SAIL — Subject Authorization & Intervention Layer.

Runtime authorization facade for agent tool execution.  Callers use it as:

    decision = sail.authorize(
        subject=agent_id,
        action="tool.execute",
        resource=tool_name,
        parameters=arguments,
    )

    if decision.allow:
        result = tool.execute(arguments)
    else:
        raise AuthorizationError(decision.reason)

Design principles (mirroring the repo's approval-gate invariants):

* Fail closed: any error, unknown input, or missing context yields a DENY
  decision — never an implicit allow.
* Risk-score-to-policy mapping is delegated to ``approval_gate.risk`` so the
  constitutional thresholds (authz-impacting ops floor at 60 / DUAL_APPROVAL,
  gate modifications floor at 100 / RESTRICTED) cannot drift here.
* Every decision produces an audit record via
  ``approval_gate.risk.create_approval_record``.

Deferred (queued) jobs are supported natively::

    enqueue(job)                     # hours earlier

    decision = sail.authorize(
        subject=job.owner,
        action=job.action,
        resource=job.resource,
    )
    if decision.allow:
        execute(job)

Because a job can sit in the queue for hours, authorize() stamps each
decision with the time it was evaluated and enforces a freshness TTL
(default 15 minutes, configurable per lifecycle profile or globally).
A stale decision fails closed -- approvals must reflect current policy,
not whatever the gate looked like when the job was enqueued.
"""

from __future__ import annotations

import time as _time_module
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional

from approval_gate.risk import (
    ApprovalPolicy,
    apply_overrides,
    determine_policy,
    create_approval_record,
)

__all__ = [
    "AuthorizationError",
    "AuthorizationDecision",
    "Job",
    "enqueue",
    "drain_ready",
    "authorize",
    "register_tool",
    "register_lifecycle_action",
    "set_decision_ttl",
    "register_senior_approver",
    "register_qualified_approver",
    "approve",
    "revoke_approval",
    "revoke_tool",
    "revoke_resource",
    "register_policy",
]


class AuthorizationError(Exception):
    """Raised by call sites when a decision denies the requested action."""

    def __init__(self, message: str = "authorization denied", *, decision=None):
        super().__init__(message)
        self.decision = decision


@dataclass(frozen=True)
class AuthorizationDecision:
    """Immutable outcome of an authorization check."""

    allow: bool
    policy: ApprovalPolicy
    risk_score: float
    reason: str
    record: Mapping[str, object] = field(default_factory=dict)
    # Wall-clock time (epoch seconds) the decision was evaluated.  Queued
    # jobs are authorized hours after enqueue; consumers must treat a
    # decision older than ``ttl_seconds`` as stale and re-authorize.
    evaluated_at: float = 0.0
    ttl_seconds: float = 0.0

    def __bool__(self) -> bool:  # convenience: `if decision:` mirrors allow
        return self.allow

    @property
    def fresh(self) -> bool:
        """True while the decision is still within its validity TTL."""
        if not self.allow:
            return False
        if self.ttl_seconds <= 0:
            return True
        return (_now_epoch() - self.evaluated_at) <= self.ttl_seconds


# ---------------------------------------------------------------------------
# Tool registry: name -> {risk_score, affects_authz, modifies_approval_gate}
# Unknown tools default to the maximum-risk profile (fail closed).
# ---------------------------------------------------------------------------

_DEFAULT_TOOL_PROFILE = {
    "risk_score": 100.0,
    "affects_authz": True,
    "modifies_approval_gate": False,
}

_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

# Revoked tools / resources.  A revoked entry DENYs even when a valid
# profile (or a previously issued decision) still exists -- revocation is
# checked first in authorize(), so "revoke then re-authorize" always fails
# closed regardless of what the cached decision said.
_REVOKED_TOOLS: set[str] = set()
_REVOKED_RESOURCES: set[str] = set()


def revoke_tool(name: str) -> None:
    """Retire a registered tool; subsequent authorizations must DENY."""
    _REVOKED_TOOLS.add(str(name))


def revoke_resource(resource_id: str) -> None:
    """Revoke all standing approvals for one resource instance id."""
    _REVOKED_RESOURCES.add(str(resource_id))


# Live approval state keyed by (subject, action, resource).  authorize()
# unions these standing grants with any per-call ``approvers`` argument,
# and revoke_approval() removes them *before* execution so a stale ALLOW
# decision can never carry a revoked approval across the boundary.
_APPROVAL_LEDGER: dict[tuple[str, str, str], set[str]] = {}


def approve(
    *, subject: str, action: str, resource: str, approver: str
) -> None:
    """Record ``approver``'s standing approval for one exact grant."""
    _APPROVAL_LEDGER.setdefault(
        (str(subject), str(action), str(resource)), set()
    ).add(str(approver))

# Lifecycle-operation profiles keyed by action name.  These govern runtime
# state transitions that are not tied to one specific tool/workflow id --
# e.g. ``workflow.resume`` and ``checkpoint.restore`` -- so an authorize()
# call whose *resource* is an instance id (workflow.id / checkpoint.id) can
# still be scored deterministically instead of falling back to the
# max-risk default.  Restore rewrites live agent state, so it is treated as
# authz-impacting (>= 60 -> DUAL_APPROVAL floor via apply_overrides).
_LIFECYCLE_PROFILES: dict[str, dict[str, Any]] = {
    "workflow.resume": {
        "risk_score": 45.0,           # SENIOR_APPROVAL band
        "affects_authz": False,
        "modifies_approval_gate": False,
    },
    "checkpoint.restore": {
        # EB-002 policy: risk_score 60 -> DUAL_APPROVAL band.  Stated
        # explicitly so the YAML policy and the code cannot drift apart.
        "risk_score": 60.0,           # DUAL_APPROVAL (two distinct qualified approvers)
        "affects_authz": True,        # -> >= AUTHZ_RISK_FLOOR (60), never relaxable
        "modifies_approval_gate": False,
    },
}

# Action-level overrides applied on top of the tool's base score.
_ACTION_OVERRIDES: Mapping[str, tuple[float, float]] = {
    # (lower_bound, new_score) rules; see approval_gate.risk.apply_overrides
}

# Roster of senior operators allowed to satisfy SENIOR_APPROVAL policy.
# Empty by default -> SENIOR_APPROVAL requests fail closed until the
# deployment registers its seniors explicitly.
_SENIOR_ROSTER: set[str] = set()

# Registry of *qualified* approvers for DUAL_APPROVAL operations (e.g.
# checkpoint restore).  Unlike the senior roster this governs which
# identities count as independent, authorized approvers at all; anything
# not listed here is treated as an unqualified signer and fails closed.
_QUALIFIED_APPROVERS: set[str] = set()


def register_qualified_approver(name: str) -> None:
    """Add ``name`` to the qualified-approver registry for dual approval."""
    _QUALIFIED_APPROVERS.add(str(name))


def revoke_approval(
    *, subject: str, action: str, resource: str, approver: str
) -> bool:
    """Withdraw ``approver``'s standing approval for one exact grant.

    Approvals are live state, not receipts: EB-001 requires that an
    approval revoked *before execution* causes the next authorize() call
    to DENY, even if an earlier decision said ALLOW.  Returns True when a
    matching grant existed and was removed.
    """
    key = (str(subject), str(action), str(resource))
    grants = _APPROVAL_LEDGER.get(key)
    if grants and str(approver) in grants:
        grants.discard(str(approver))
        return True
    return False

# ---------------------------------------------------------------------------
# Clock & decision freshness (queued jobs)
# ---------------------------------------------------------------------------

def _now_epoch() -> float:
    return _time_module.time()


def _to_epoch(value: Any) -> Optional[float]:
    """Coerce a test-supplied clock value to epoch seconds.

    Accepts epoch numbers, ``datetime`` instances, and module-like clocks
    exposing ``utcnow()`` (the shape ``create_approval_record`` consumes).
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()
    utcnow = getattr(value, "utcnow", None)
    if callable(utcnow):
        naive = utcnow()  # module-style test clock: naive-UTC datetime
        if isinstance(naive, datetime):
            if naive.tzinfo is None:
                naive = naive.replace(tzinfo=timezone.utc)
            return naive.timestamp()
        return _to_epoch(naive)
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _record_clock(value: Any) -> Any:
    """Adapt an injected clock for ``create_approval_record``.

    The gate's record builder expects a module-like object exposing
    ``utcnow()``; SAIL callers may inject plain epoch floats or datetimes,
    so normalize everything to that shape (pass through objects that
    already provide ``utcnow``, e.g. the ``datetime`` module itself).
    """
    if hasattr(value, "utcnow"):
        return value
    epoch = _to_epoch(value)
    if epoch is None:
        return value  # let the record builder surface the bad clock
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return type(
        "_FixedClock",
        (),
        {"utcnow": staticmethod(lambda: dt.replace(tzinfo=None))},
    )()


# How long an ALLOW decision stays actionable.  Queued jobs are authorized
# at execution time (fresh evaluation), so this TTL mainly guards callers
# that cache decisions between enqueue and execute.  <= 0 disables expiry.
DEFAULT_DECISION_TTL_SECONDS = 15 * 60.0
_DECISION_TTL = DEFAULT_DECISION_TTL_SECONDS


def set_decision_ttl(seconds: Optional[float]) -> None:
    """Set the global decision-freshness TTL (None restores the default)."""
    global _DECISION_TTL
    _DECISION_TTL = (
        DEFAULT_DECISION_TTL_SECONDS if seconds is None else float(seconds)
    )


# ---------------------------------------------------------------------------
# Deferred job queue: enqueue now, authorize + execute later
# ---------------------------------------------------------------------------

@dataclass
class Job:
    """A unit of deferred work governed by SAIL at execution time."""

    owner: str
    action: str
    resource: str
    parameters: Mapping[str, Any] = field(default_factory=dict)
    id: str = ""
    enqueued_at: float = 0.0
    status: str = "queued"          # queued | running | done | denied | failed
    decision: Optional[AuthorizationDecision] = None


_JOB_QUEUE: list[Job] = []


def _job_field(job: Any, name: str, default: Any = None) -> Any:
    """Read a queue field, tolerating caller-defined job classes.

    Producers often enqueue their own job objects (duck-typed with
    ``owner``/``action``/``resource``); missing bookkeeping fields get
    defaults written back rather than raising AttributeError.
    """
    if hasattr(job, name):
        return getattr(job, name)
    value = default() if callable(default) else default
    try:
        setattr(job, name, value)
    except (AttributeError, TypeError):
        pass  # read-only object: use the default without persisting it
    return value


def enqueue(job: Any) -> Any:
    """Add ``job`` to the deferred queue.

    No authorization happens here -- the gate is evaluated when the job
    actually runs, so policy changes during the queue delay take effect
    (fail-closed on drift rather than honoring stale approvals).
    """
    if _job_field(job, "enqueued_at", 0.0) <= 0:
        job.enqueued_at = _now_epoch()
    _job_field(job, "status", "queued")
    _JOB_QUEUE.append(job)
    return job


def pending_jobs() -> list[Any]:
    """Snapshot of still-queued jobs (does not mutate the queue)."""
    return [j for j in _JOB_QUEUE if getattr(j, "status", "queued") == "queued"]


def drain_ready(
    executor: Callable[[Any], Any],
    *,
    approvers_for: Optional[Callable[[Any], Optional[list[str]]]] = None,
    clock: Any = None,
    id_factory: Any = None,
) -> list[tuple[Any, AuthorizationDecision]]:
    """Authorize and execute every queued job, oldest first.

    Each job gets a *fresh* :func:`authorize` call at execution time; jobs
    whose decision denies are skipped (status ``denied``) and never handed
    to ``executor``.  Executor exceptions mark the job ``failed``, release
    it back to ``queued`` for retry, and abort the drain after recording
    the failure (fail closed: a broken executor must not silently chew
    through the queue).  Returns (job, decision) pairs for the jobs
    attempted before the abort.
    """
    results: list[tuple[Any, AuthorizationDecision]] = []
    for job in [j for j in _JOB_QUEUE
                if getattr(j, "status", "queued") == "queued"]:
        job.status = "running"
        approvers = approvers_for(job) if approvers_for else None
        decision = authorize(
            subject=_job_field(job, "owner", ""),
            action=_job_field(job, "action", ""),
            resource=_job_field(job, "resource", ""),
            parameters=_job_field(job, "parameters", dict) or {},
            approvers=approvers,
            clock=clock,
            id_factory=id_factory,
        )
        job.decision = decision
        if not decision.allow:
            job.status = "denied"
            results.append((job, decision))
            continue
        try:
            executor(job)
        except Exception:
            job.status = "queued"  # transient failure -> eligible for retry
            results.append((job, decision))
            raise
        job.status = "done"
        results.append((job, decision))
    return results


def register_senior_approver(name: str) -> None:
    """Add ``name`` to the senior-operator roster."""
    _SENIOR_ROSTER.add(str(name))


def register_tool(
    name: str,
    risk_score: float = 0.0,
    *,
    affects_authz: bool = False,
    modifies_approval_gate: bool = False,
) -> None:
    """Register a tool with its baseline risk profile."""
    _TOOL_REGISTRY[name] = {
        "risk_score": float(risk_score),
        "affects_authz": bool(affects_authz),
        "modifies_approval_gate": bool(modifies_approval_gate),
    }


def register_lifecycle_action(
    action: str,
    risk_score: float,
    *,
    affects_authz: bool = False,
    modifies_approval_gate: bool = False,
    ttl_seconds: Optional[float] = None,
) -> None:
    """Register (or override) the risk profile for a lifecycle action.

    Intended for actions like ``workflow.resume`` or ``checkpoint.restore``
    where the governed surface is the action itself rather than a named
    tool in :func:`register_tool`.  ``ttl_seconds`` optionally overrides the
    decision-freshness window for this action (useful for queued jobs whose
    approvals must expire faster or slower than the global default).
    """
    _LIFECYCLE_PROFILES[action] = {
        "risk_score": float(risk_score),
        "affects_authz": bool(affects_authz),
        "modifies_approval_gate": bool(modifies_approval_gate),
        **({"ttl_seconds": float(ttl_seconds)} if ttl_seconds is not None else {}),
    }


def register_policy(policy: ApprovalPolicy) -> None:
    """Placeholder hook for per-subject policy overrides (not yet enforced).

    Kept explicit rather than silently absent so integrators do not assume
    looser semantics than actually exist.
    """
    raise NotImplementedError(
        "per-subject policy overrides are not implemented; SAIL fails closed"
    )


def _score_operation(profile: Mapping[str, Any], action: str) -> float:
    return apply_overrides(
        profile["risk_score"],
        affects_authz=bool(profile.get("affects_authz")),
        modifies_approval_gate=bool(profile.get("modifies_approval_gate")),
        overrides={action: _ACTION_OVERRIDES[action]}
        if action in _ACTION_OVERRIDES
        else None,
    )


def authorize(
    *,
    subject: str,
    action: str,
    resource: str,
    parameters: Optional[Mapping[str, Any]] = None,
    approvers: Optional[list[str]] = None,
    break_glass: bool = False,
    clock: Any = None,
    id_factory: Any = None,
) -> AuthorizationDecision:
    """Evaluate whether ``subject`` may perform ``action`` on ``resource``.

    Returns an :class:`AuthorizationDecision`; callers must branch on
    ``decision.allow`` and never execute the action otherwise.

    Execution-boundary invariant: every governed operation (tool
    invocation, workflow resume, checkpoint restore, queued-job execution)
    converges on this single chokepoint *immediately prior* to execution.
    Planning-time / scheduling-time / creation-time approvals never count;
    a decision is only valid if it was produced here, at this instant,
    against live revocation state.

    Denial rules (all fail-closed):
      * Missing/blank subject, action, or resource -> DENY.
      * Revoked tool or revoked resource id -> DENY (checked first, so
        revocation beats any previously issued ALLOW).
      * Unregistered tool -> treated as max-risk -> DENY (RESTRICTED).
      * RESTRICTED band (score >= 80) -> DENY unless ``break_glass`` AND two
        distinct senior approvers are supplied.
      * DUAL_APPROVAL band -> requires two *distinct qualified* approvers
        (identical approvers collapse to one grant; unqualified signers do
        not count -- EB-002).
      * SENIOR_APPROVAL band -> requires one approver from the senior
        roster (EB-001: non-rostered approvers DENY).
      * SINGLE_APPROVAL band -> requires one approver.
      * AUTONOMOUS band -> allowed without human sign-off (EB-003:
        registered low-risk tools keep their autonomous path).

    Approvals considered are the union of the per-call ``approvers`` list
    and standing grants in the approval ledger for this exact
    (subject, action, resource) triple -- so revoke_approval() before
    execution flips the very next authorize() call to DENY.

    Queued jobs: the decision is evaluated at *execution* time and stamped
    with ``evaluated_at``/``ttl_seconds``; a cached decision whose TTL has
    elapsed reports ``fresh == False`` and must be re-authorized before the
    work runs.  ``clock`` (epoch seconds or datetime) overrides "now" for
    deterministic tests.
    """
    now = _to_epoch(clock) if clock is not None else _now_epoch()
    if now is None:
        return _deny(0.0, ApprovalPolicy.RESTRICTED,
                     "invalid clock supplied: fail closed")

    if not subject or not action or not resource:
        return _deny(0.0, ApprovalPolicy.RESTRICTED,
                     "missing subject/action/resource: fail closed", now=now)

    # Revocation is checked before anything else: a revoked tool or
    # resource denies even when a valid profile and prior ALLOW exist.
    if str(resource) in _REVOKED_TOOLS:
        return _deny(0.0, ApprovalPolicy.RESTRICTED,
                     f"tool {resource!r} has been revoked: fail closed",
                     now=now)
    if str(resource) in _REVOKED_RESOURCES:
        return _deny(0.0, ApprovalPolicy.RESTRICTED,
                     f"resource {resource!r} authorization revoked: "
                     "fail closed", now=now)

    profile = _TOOL_REGISTRY.get(resource)
    if profile is None:
        # Resource is an instance id (workflow.id, checkpoint.id, job
        # resource, ...); fall back to the action-level lifecycle profile
        # before the max-risk default so governed transitions score
        # deterministically.
        profile = _LIFECYCLE_PROFILES.get(action, _DEFAULT_TOOL_PROFILE)
    score = _score_operation(profile, action)
    policy = determine_policy(score)
    ttl = float(profile.get("ttl_seconds", _DECISION_TTL))

    record = create_approval_record(
        score,
        operation=f"{action}:{resource}",
        actor=str(subject),
        clock=_record_clock(clock) if clock is not None else None,
        id_factory=id_factory,
        extra={"parameters_keys": sorted(parameters or {}), "subject": str(subject)},
    )

    granted = {str(a) for a in approvers or []}
    # Standing approvals recorded via approve() for this exact grant are
    # live state; they participate in every subsequent evaluation until
    # revoked (revoke_approval) -- never snapshotted into a receipt.
    granted |= set(_APPROVAL_LEDGER.get(
        (str(subject), str(action), str(resource)), ()))
    needs = {
        ApprovalPolicy.AUTONOMOUS: 0,
        ApprovalPolicy.SINGLE_APPROVAL: 1,
        ApprovalPolicy.SENIOR_APPROVAL: 1,
        ApprovalPolicy.DUAL_APPROVAL: 2,
        ApprovalPolicy.RESTRICTED: None,  # deny-by-default
    }[policy]

    # The subject cannot approve their own request -- approvals must be
    # *independent* humans (or senior operators) distinct from the actor.
    granted.discard(str(subject))

    def _decide(allow: bool, reason: str) -> AuthorizationDecision:
        return AuthorizationDecision(allow, policy, score, reason, record,
                                     evaluated_at=now, ttl_seconds=ttl)

    if needs is None:
        if break_glass and len(granted) >= 2:
            return _decide(True, "break-glass override")
        return _decide(False, f"policy {policy} denies by default")

    if len(granted) < needs:
        return _decide(
            False,
            f"policy {policy} requires {needs} approver(s), got {len(granted)}")

    if policy is ApprovalPolicy.SENIOR_APPROVAL:
        # EB-001: the approver must come from the registered senior
        # roster; anything not on it fails closed.  An empty roster means
        # no senior operators are known, so every SENIOR_APPROVAL request
        # is denied.
        seniors = granted & _SENIOR_ROSTER
        if not seniors:
            return _decide(
                False, "senior approver roster unavailable or unsatisfied")

    if policy is ApprovalPolicy.DUAL_APPROVAL:
        # EB-002: dual approval must come from two *distinct qualified*
        # approvers.  Identical signatures collapse to one grant above
        # (set semantics), and unqualified signers never count toward the
        # bar.  The qualification registry is required for DUAL_APPROVAL:
        # with no registered qualified approvers, every request fails
        # closed rather than trusting unknown identities.
        qualified = granted & _QUALIFIED_APPROVERS
        if len(qualified) < needs:
            return _decide(
                False,
                f"dual approval requires {needs} distinct qualified "
                f"approvers, got {len(qualified)}")

    return _decide(True, "approved")


def _deny(
    score: float,
    policy: ApprovalPolicy,
    reason: str,
    *,
    now: Optional[float] = None,
) -> AuthorizationDecision:
    return AuthorizationDecision(False, policy, score, reason, {},
                                 evaluated_at=(now if now is not None
                                               else _now_epoch()),
                                 ttl_seconds=0.0)
