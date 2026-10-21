"""ABIDE reference-monitor checks wired into the execution boundary.

This module is the *parity mirror* of the Rust ABIDE-Harness specification:
the same predicate lattice, evaluated in Python inside the Sovereign Engine's
dispatch path so the audit story stays language-agnostic.

Reference monitor predicate (all conjuncts must hold before dispatch):

    Authorized(a, ctx)  <=>  ValidSig(token)
                          & EpochMatch(token.epoch, sts.epoch)
                          & NotExpired(ctx.current_epoch <= token.expires_at)
                          & NotConsumed(token.nonce)          # single-use liveness
                          & A_i subset_of P_root              # attenuation lattice
                          & a in A_i                          # action membership

Design constraints inherited from the frozen SAIL spec:

* **Fail closed.** Any missing input, malformed token, or unverifiable
  signature raises :class:`SecurityError`; there is no boolean "force" path.
* **Single-use liveness.** Consumed nonces are remembered for the lifetime of
  the boundary instance; replay of a previously redeemed token is a security
  violation (raises), not a policy denial (returns False).
* **Capability attenuation is monotone.** Derived capability sets may only
  shrink (:func:`attenuate`); any attempt to widen a set escapes the lattice
  and raises.
* **Separation of concerns.** Signature/epoch/expiry/subset breaches raise and
  quarantine; plain *policy* misses (action not in A_i) return ``False`` so
  ordinary denials do not look like attacks in the audit ledger.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol, Set

from sovereign_engine.execution.boundary import ExecutionBoundary


class AuditEmitter(Protocol):
    """Minimal structural interface for the SEAL audit layer.

    Anything with an ``emit(record)`` method qualifies (a logger adapter, a
    ledger writer, a test recorder).  The boundary never blocks on the audit
    sink failing -- but neither does it swallow silently; emitter exceptions
    are recorded in-band on the boundary observations.
    """

    def emit(self, record: dict[str, Any]) -> None: ...


class SecurityError(Exception):
    """Raised when an ABIDE reference monitor security invariant is breached."""


class SignatureVerifier(Protocol):
    def verify(self, message: bytes, signature: bytes) -> bool: ...


@dataclass(frozen=True, slots=True)
class Ed25519Verifier:
    """Concrete verifier backed by the ``cryptography`` Ed25519 primitive."""

    public_key: Any  # cryptography.hazmat.primitives.asymmetric.ed25519 key

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self.public_key.verify(signature, message)
            return True
        except Exception:
            return False


def canonical_message(token: "ExecutionToken") -> bytes:
    """Deterministic signing/verification material for a token.

    Includes agent, epoch, expiry, nonce and the *sorted* capability tuple so
    that substituting any element (identity swap, epoch bump, capability
    widening) changes the digest and fails signature verification rather than
    policy interpretation.
    """
    caps = "|".join(sorted(token.capabilities))
    return (
        f"ABIDE-TOKEN:v1|{token.agent_id}|{token.epoch}|{token.expires_at}"
        f"|{token.nonce}|{caps}"
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class ExecutionToken:
    """A signed, single-use execution grant presented at the boundary.

    Temporal semantics (ABIDE A4 / STS window parity):

    * ``epoch``      -- mint epoch; a grant is live **only** in the epoch it
                        was minted in (window parity).  Future-dated tokens
                        are inert forgeries; old-epoch presentations raise as
                        staleness/replay rather than extending inside
                        ``expires_at``.
    * ``expires_at`` -- inclusive last valid epoch, checked first so that an
                        expired grant is diagnosed as expiry (dominant cause)
                        before the mismatch symptom.
    * Liveness (single-use nonce) gates every dispatch independently of the
      temporal window.
    """

    agent_id: str
    epoch: int
    expires_at: int
    nonce: str
    capabilities: frozenset[str]
    signature: bytes

    def as_record(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "epoch": self.epoch,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "capabilities": sorted(self.capabilities),
        }


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Per-dispatch context handed to the reference monitor."""

    agent_id: str
    current_epoch: int
    capabilities: Set[str]
    root_policy: Set[str]
    token_consumed: bool = False


@dataclass
class ABIDEExecutionBoundary:
    """Enforces ABIDE reference monitor invariants at the dispatch boundary.

    Wraps (does not replace) :class:`ExecutionBoundary`: the physical interlock
    still performs its independent digest/single-use/state-drift checks.  This
    layer adds the token-level checks: Ed25519 signature, epoch match, expiry,
    nonce liveness, and the ``A_i subset_of P_root`` attenuation invariant.
    """

    root_policy: Set[str]
    verifier: SignatureVerifier | None = None
    boundary: ExecutionBoundary = field(default_factory=ExecutionBoundary)
    audit: AuditEmitter | None = None
    consumed_nonces: Set[str] = field(default_factory=set)
    #: resources quarantined by this monitor after a security breach
    quarantined: Set[str] = field(default_factory=set)
    on_breach: Callable[[str], None] | None = None

    # -- reference monitor core ----------------------------------------------

    def verify_token(self, token: ExecutionToken, *, current_epoch: int) -> None:
        """Signature + liveness-window + expiry validation.  Raises on breach.

        Temporal ordering mirrors the STS window semantics: an *expired* grant
        is diagnosed as expired before any epoch-mismatch reading, so audit
        records name the dominant cause (staleness) rather than a symptom.
        """
        if self.verifier is None:
            raise SecurityError("no signature verifier configured: fail closed")
        if not self.verifier.verify(canonical_message(token), token.signature):
            self._breach(f"signature invalid for agent {token.agent_id}", token=None)
            raise SecurityError("Ed25519 signature verification failed")
        if current_epoch > token.expires_at:
            self._breach(
                f"token expired: expires_at={token.expires_at} now={current_epoch}",
                token=token,
            )
            raise SecurityError("token is expired")
        # Window parity (ABIDE A4): a grant is live only in the epoch it was
        # minted in.  Staleness inside [epoch, expires_at] does not extend the
        # grant -- presenting an old-epoch token is treated as replay/staleness
        # and raises; future-dated tokens are inert forgeries.
        if token.epoch != current_epoch:
            self._breach(
                f"epoch mismatch: token={token.epoch} current={current_epoch}",
                token=token,
            )
            raise SecurityError("token epoch does not match the STS epoch")

    def authorize_execution(
        self,
        context: ExecutionContext,
        token: ExecutionToken,
        action: str,
    ) -> bool:
        """Full predicate: Sig & Epoch & Expiry & Liveness & A_i⊆P_root & a∈A_i.

        Returns ``True`` (dispatch authorized) or ``False`` (ordinary policy
        denial).  Raises :class:`SecurityError` for security-invariant breaches
        (bad signature, replayed nonce, escaped capability set, identity swap).
        """
        # 0. Identity binding: token must name the acting agent (A3 swap guard)
        if token.agent_id != context.agent_id:
            self._breach(
                f"identity substitution: token agent {token.agent_id!r} != "
                f"context agent {context.agent_id!r}",
                token=token,
            )
            raise SecurityError("token subject does not match execution context")

        # 1. Single-use liveness (replay / resurrection attack surface)
        if token.nonce in self.consumed_nonces:
            self._breach(
                f"token nonce {token.nonce} already consumed (replay)",
                token=token,
            )
            raise SecurityError(f"Token {token.nonce} is consumed.")

        # 2. Signature + temporal checks
        self.verify_token(token, current_epoch=context.current_epoch)

        # 3. Capability subset invariant  A_i ⊆ P_root
        if not context.capabilities.issubset(self.root_policy):
            self._breach(
                "agent capabilities exceed root policy P_root", token=token
            )
            raise SecurityError("capability set escapes root policy bounds")
        # Token capabilities must also sit inside the lattice, and inside the
        # session capability set actually presented.
        if not token.capabilities.issubset(self.root_policy):
            self._breach("token capabilities exceed root policy P_root", token=token)
            raise SecurityError("token capability set escapes root policy bounds")
        if not token.capabilities.issubset(context.capabilities):
            self._breach(
                "token claims capabilities outside the session context", token=token
            )
            raise SecurityError("token capability set exceeds session capabilities")

        # 4. Action membership  a ∈ A_i  (policy denial, not a breach)
        if action not in token.capabilities or action not in context.capabilities:
            self._emit(
                {"event": "DENY", "action": action, "agent": context.agent_id,
                 "detail": f"action '{action}' not within A_i"}
            )
            return False

        # 5. Mark token consumed (single-use enforcement)
        self.consumed_nonces.add(token.nonce)
        self._emit(
            {"event": "AUTHORIZE", "action": action, "agent": context.agent_id,
             "nonce": token.nonce, "epoch": context.current_epoch}
        )
        return True

    def authorize_and_dispatch(
        self,
        context: ExecutionContext,
        action: str,
        token_nonce: str,
        *,
        token: ExecutionToken | None = None,
        permit: Any | None = None,
    ) -> bool:
        """Compatibility entrypoint wiring the monitor into the dispatch loop.

        Two supported shapes:
        * Modern: pass the full ``token`` (and optionally a physical
          ``ActuationPermit``) -- the complete reference-monitor predicate runs
          and the permit is redeemed through the wrapped ExecutionBoundary.
        * Legacy blueprint shape: ``(context, action, token_nonce)`` -- the
          nonce is treated as a caller-held handle into ``consumed_nonces`` and
          checked against ``context.token_consumed`` plus the capability
          lattice exactly as in the original integration blueprint.
        """
        if token is not None:
            approved = self.authorize_execution(context, token, action)
            if approved and permit is not None:
                # Redeem through the physical interlock; failures propagate as
                # UnauthorizedActuationError -- the boundary remains the last
                # line of defence even after token-level approval.
                self.boundary.engage(permit, current_state=context.__dict__.get(
                    "state", getattr(permit, "expected_state", "")
                ), payload={"action": action})
            return approved

        # -- legacy blueprint path (no structured token available) --
        if token_nonce in self.consumed_nonces or context.token_consumed:
            self._breach(
                f"token nonce {token_nonce} already consumed "
                "(Resurrection/Replay attack).",
                token=None,
            )
            raise SecurityError(f"Token {token_nonce} is consumed.")
        if not context.capabilities.issubset(self.root_policy):
            self._breach("Agent capabilities exceed root policy P_root.", token=None)
            raise SecurityError("Capability set escapes root policy bounds.")
        if action not in context.capabilities:
            self._emit(
                {"event": "DENY", "action": action, "agent": context.agent_id,
                 "detail": f"action '{action}' denied for agent {context.agent_id}"}
            )
            return False
        self.consumed_nonces.add(token_nonce)
        self._emit(
            {"event": "AUTHORIZE", "action": action, "agent": context.agent_id,
             "nonce": token_nonce, "epoch": context.current_epoch}
        )
        return True

    # -- capability attenuation lattice --------------------------------------

    def attenuate(
        self, source: Set[str] | frozenset[str], granted_subset: Set[str]
    ) -> frozenset[str]:
        """Derive a child capability set A_j from A_i with A_j ⊆ A_i ⊆ P_root.

        Monotonicity is enforced structurally: widening attempts raise
        :class:`SecurityError`.  Attenuated sets are returned frozen so they
        cannot be mutated back toward the parent.
        """
        derived = frozenset(granted_subset)
        if not derived.issubset(source):
            escaped = sorted(derived - frozenset(source))
            self._breach(
                f"capability attenuation attempted to widen: {escaped}", token=None
            )
            raise SecurityError(
                f"attenuation violates lattice: {escaped} not in parent set"
            )
        if not derived.issubset(self.root_policy):
            self._breach("attenuated set escapes P_root", token=None)
            raise SecurityError("attenuated capability set escapes root policy")
        return derived

    # -- internals ------------------------------------------------------------

    def _breach(self, detail: str, *, token: ExecutionToken | None) -> None:
        record: dict[str, Any] = {"event": "SECURITY_BREACH", "detail": detail}
        if token is not None:
            record["token"] = token.as_record()
        self._emit(record)
        if self.on_breach is not None:
            resource = token.agent_id if token is not None else "boundary"
            self.quarantined.add(resource)
            self.on_breach(resource)

    def _emit(self, record: dict[str, Any]) -> None:
        record.setdefault(
            "fingerprint",
            hashlib.sha256(repr(sorted(record.items())).encode()).hexdigest()[:16],
        )
        if self.audit is not None:
            try:
                self.audit.emit(record)
            except Exception as exc:  # audit failure must not open the gate
                self.boundary.observations.append(
                    {"outcome": "AUDIT_EMIT_FAILED", "detail": str(exc)}
                )


def attenuating_boundary_for(
    parent: ABIDEExecutionBoundary, granted_subset: Set[str]
) -> ABIDEExecutionBoundary:
    """Derive a child boundary whose root policy is A_j ⊆ P_root (lattice edge).

    The child shares the parent's physical interlock and audit sink so that
    single-use liveness and telemetry remain global properties of the dispatch
    path; only the policy ceiling narrows.  Widening raises ``SecurityError``
    via :meth:`ABIDEExecutionBoundary.attenuate`.
    """
    derived = parent.attenuate(parent.root_policy, granted_subset)
    return ABIDEExecutionBoundary(
        root_policy=set(derived),
        verifier=parent.verifier,
        boundary=parent.boundary,
        audit=parent.audit,
        consumed_nonces=parent.consumed_nonces,
        on_breach=parent.on_breach,
    )


__all__ = [
    "AuditEmitter",
    "SecurityError",
    "SignatureVerifier",
    "Ed25519Verifier",
    "canonical_message",
    "ExecutionToken",
    "ExecutionContext",
    "ABIDEExecutionBoundary",
    "attenuating_boundary_for",
]
