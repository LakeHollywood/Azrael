#!/usr/bin/env python3
"""Risk scoring helpers for tactical edge operations.

Provides the ``Operation`` model and the authorization-impact risk floor:
any operation that affects authorization state is considered high-risk and
its score is clamped to at least 60.
"""

from dataclasses import dataclass, field
from typing import Optional

AUTHZ_IMPACTING_OPERATIONS = frozenset({
    "grant_role",
    "revoke_role",
    "modify_policy",
    "rotate_credentials",
    "change_acl",
})


@dataclass
class Operation:
    """A single auditable operation on the edge node."""

    name: str
    actor: str = "unknown"
    affects_authz_flag: bool = False
    metadata: dict = field(default_factory=dict)

    def affects_authz(self) -> bool:
        """Return True if this operation changes authorization state.

        Explicitly flagged operations always count; otherwise fall back to
        a lookup against the known authz-impacting operation names.
        """
        return self.affects_authz_flag or self.name in AUTHZ_IMPACTING_OPERATIONS


def apply_risk_floor(risk_score: float, operation: Operation) -> float:
    """Apply the authorization-impact risk floor.

    If ``operation.affects_authz()`` is true, raise ``risk_score`` to at
    least 60 (never lower an already-higher score).
    """
    if operation.affects_authz():
        risk_score = max(risk_score, 60)
    return risk_score
