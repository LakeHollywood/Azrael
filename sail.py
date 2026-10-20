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
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from approval_gate.risk import (
    ApprovalPolicy,
    apply_overrides,
    determine_policy,
    create_approval_record,
)

__all__ = [
    "AuthorizationError",
    "AuthorizationDecision",
    "authorize",
    "register_tool",
    "register_lifecycle_action",
    "register_senior_approver",
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

    def __bool__(self) -> bool:  # convenience: `if decision:` mirrors allow
        return self.allow


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
        "risk_score": 55.0,           # escalated to >= 60 by the authz floor
        "affects_authz": True,        # -> DUAL_APPROVAL
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
) -> None:
    """Register (or override) the risk profile for a lifecycle action.

    Intended for actions like ``workflow.resume`` or ``checkpoint.restore``
    where the governed surface is the action itself rather than a named
    tool in :func:`register_tool`.
    """
    _LIFECYCLE_PROFILES[action] = {
        "risk_score": float(risk_score),
        "affects_authz": bool(affects_authz),
        "modifies_approval_gate": bool(modifies_approval_gate),
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

    Denial rules (all fail-closed):
      * Missing/blank subject, action, or resource -> DENY.
      * Unregistered tool -> treated as max-risk -> DENY (RESTRICTED).
      * RESTRICTED band (score >= 80) -> DENY unless ``break_glass`` AND two
        distinct senior approvers are supplied.
      * DUAL_APPROVAL band -> requires two distinct approvers.
      * SENIOR_APPROVAL band -> requires one senior approver.
      * SINGLE_APPROVAL band -> requires one approver.
      * AUTONOMOUS band -> allowed without human sign-off.
    """
    if not subject or not action or not resource:
        return _deny(0.0, ApprovalPolicy.RESTRICTED,
                     "missing subject/action/resource: fail closed")

    profile = _TOOL_REGISTRY.get(resource)
    if profile is None:
        # Resource is an instance id (workflow.id, checkpoint.id, ...);
        # fall back to the action-level lifecycle profile before the
        # max-risk default so governed transitions score deterministically.
        profile = _LIFECYCLE_PROFILES.get(action, _DEFAULT_TOOL_PROFILE)
    score = _score_operation(profile, action)
    policy = determine_policy(score)

    record = create_approval_record(
        score,
        operation=f"{action}:{resource}",
        actor=str(subject),
        clock=clock,
        id_factory=id_factory,
        extra={"parameters_keys": sorted(parameters or {}), "subject": str(subject)},
    )

    granted = {str(a) for a in approvers or []}
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

    if needs is None:
        if break_glass and len(granted) >= 2:
            return AuthorizationDecision(True, policy, score,
                                         "break-glass override", record)
        return AuthorizationDecision(False, policy, score,
                                     f"policy {policy} denies by default",
                                     record)

    if len(granted) < needs:
        return AuthorizationDecision(
            False, policy, score,
            f"policy {policy} requires {needs} approver(s), got {len(granted)}",
            record)

    if policy is ApprovalPolicy.SENIOR_APPROVAL:
        # Senior approvals come from the registered senior roster; anything
        # not on it fails closed.  An empty roster means no senior operators
        # are known, so every SENIOR_APPROVAL request is denied.
        seniors = granted & _SENIOR_ROSTER
        if not seniors:
            return AuthorizationDecision(
                False, policy, score,
                "senior approver roster unavailable or unsatisfied", record)

    return AuthorizationDecision(True, policy, score, "approved", record)


def _deny(score: float, policy: ApprovalPolicy, reason: str) -> AuthorizationDecision:
    return AuthorizationDecision(False, policy, score, reason, {})
