"""ABIDE reference-monitor conformance vectors for the execution boundary.

Covers the wiring of ``verify_token`` / ``authorize_execution`` / capability
attenuation into ``src/sovereign_engine/execution/abide_monitor.py``:

* A3  identity substitution (token subject swap)        -> SecurityError
* A4  authentic replay (consumed nonce reuse)           -> SecurityError
* A5  scope/capability widening beyond P_root           -> SecurityError
* REC-style epoch/expiry staleness                      -> SecurityError
* Positive control: fully valid signed token dispatches -> True
* Denial vs breach separation: a∈/A_i returns False, never raises
* Attenuation lattice monotonicity (A_j ⊆ A_i ⊆ P_root)
* Telemetry: every authorize/deny/breach emits an audit record
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sovereign_engine.execution.abide_monitor import (
    ABIDEExecutionBoundary,
    Ed25519Verifier,
    ExecutionContext,
    ExecutionToken,
    SecurityError,
    attenuating_boundary_for,
    canonical_message,
)


class Recorder:
    """Minimal SEAL-shaped audit sink capturing emitted records."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def emit(self, record: dict[str, Any]) -> None:
        self.records.append(record)

    def events(self) -> list[str]:
        return [r["event"] for r in self.records]


@pytest.fixture(name="signing_key")
def _signing_key() -> Ed25519PrivateKey:
    # Deterministic test key material only; zero-entropy fixture seed.
    return Ed25519PrivateKey.generate()


@pytest.fixture(name="other_key")
def _other_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


ROOT = {"actuate", "read", "configure"}


def make_token(
    key: Ed25519PrivateKey,
    *,
    agent_id: str = "agent-1",
    epoch: int = 5,
    expires_at: int = 8,
    nonce: str = "n-1",
    capabilities: tuple[str, ...] = ("actuate", "read"),
) -> ExecutionToken:
    caps = frozenset(capabilities)
    unsigned = ExecutionToken(
        agent_id=agent_id,
        epoch=epoch,
        expires_at=expires_at,
        nonce=nonce,
        capabilities=caps,
        signature=b"",
    )
    sig = key.sign(canonical_message(unsigned))
    return replace(unsigned, signature=sig)


@pytest.fixture(name="monitor")
def _monitor(signing_key: Ed25519PrivateKey) -> ABIDEExecutionBoundary:
    return ABIDEExecutionBoundary(
        root_policy=set(ROOT),
        verifier=Ed25519Verifier(signing_key.public_key()),
        audit=Recorder(),
    )


def ctx(*, epoch: int = 5, caps: set[str] | None = None) -> ExecutionContext:
    return ExecutionContext(
        agent_id="agent-1",
        current_epoch=epoch,
        capabilities=caps if caps is not None else {"actuate", "read"},
        root_policy=set(ROOT),
    )


# ---------------------------------------------------------------------------
# Positive control
# ---------------------------------------------------------------------------


def test_valid_signed_token_authorizes(signing_key: Ed25519PrivateKey) -> None:
    rec = Recorder()
    mon = ABIDEExecutionBoundary(
        root_policy=set(ROOT),
        verifier=Ed25519Verifier(signing_key.public_key()),
        audit=rec,
    )
    token = make_token(signing_key)
    assert mon.authorize_execution(ctx(), token, "actuate") is True
    assert "AUTHORIZE" in rec.events()
    assert token.nonce in mon.consumed_nonces


# ---------------------------------------------------------------------------
# verify_token: signature / epoch / expiry
# ---------------------------------------------------------------------------


class _StubVerifier:
    def __init__(self, ok: bool = True) -> None:
        self.ok = ok
        self.calls: list[tuple[bytes, bytes]] = []

    def verify(self, message: bytes, signature: bytes) -> bool:
        self.calls.append((message, signature))
        return self.ok


def test_missing_verifier_fails_closed() -> None:
    mon = ABIDEExecutionBoundary(root_policy=set(ROOT))
    with pytest.raises(SecurityError, match="fail closed"):
        mon.verify_token(make_token(Ed25519PrivateKey.generate()), current_epoch=5)


def test_bad_signature_raises_and_records_breach() -> None:
    stub = _StubVerifier(ok=False)
    rec = Recorder()
    mon = ABIDEExecutionBoundary(root_policy=set(ROOT), verifier=stub, audit=rec)
    token = make_token(Ed25519PrivateKey.generate())
    with pytest.raises(SecurityError, match="signature verification failed"):
        mon.authorize_execution(ctx(), token, "actuate")
    assert "SECURITY_BREACH" in rec.events()


def test_foreign_key_signature_rejected_by_real_ed25519() -> None:
    holder = Ed25519PrivateKey.generate()
    attacker = Ed25519PrivateKey.generate()
    mon = ABIDEExecutionBoundary(
        root_policy=set(ROOT),
        verifier=Ed25519Verifier(holder.public_key()),
        audit=Recorder(),
    )
    token = make_token(attacker)  # valid Ed25519 sig, wrong authority
    with pytest.raises(SecurityError, match="signature verification failed"):
        mon.authorize_execution(ctx(), token, "actuate")


def test_epoch_mismatch_raises() -> None:
    key = Ed25519PrivateKey.generate()
    mon = ABIDEExecutionBoundary(
        root_policy=set(ROOT), verifier=Ed25519Verifier(key.public_key()), audit=Recorder()
    )
    # Future-dated forgery: mint epoch 6 presented while STS sits at epoch 5.
    token = make_token(key, epoch=6, expires_at=9)
    with pytest.raises(SecurityError, match="epoch"):
        mon.authorize_execution(ctx(epoch=5), token, "actuate")


def test_stale_epoch_within_expiry_is_replay_not_fresh_grant() -> None:
    """Older mint epoch (4) presented at current epoch 5 is inert as a grant:

    the window parity check treats pre-mint presentation strictly; after the
    STS has moved on, an unexpired-but-not-current token is rejected before
    any dispatch can consume it.
    """
    key = Ed25519PrivateKey.generate()
    mon = ABIDEExecutionBoundary(
        root_policy=set(ROOT), verifier=Ed25519Verifier(key.public_key()), audit=Recorder()
    )
    token = make_token(key, epoch=4, expires_at=8)
    # A4 parity: authentic content, wrong temporal position -> breach, no dispatch.
    with pytest.raises(SecurityError):
        mon.authorize_execution(ctx(epoch=5), token, "actuate")


def test_expired_token_raises() -> None:
    key = Ed25519PrivateKey.generate()
    mon = ABIDEExecutionBoundary(
        root_policy=set(ROOT), verifier=Ed25519Verifier(key.public_key()), audit=Recorder()
    )
    # Token minted at epoch 7, valid through epoch 8; STS has advanced to 9.
    token = make_token(key, epoch=7, expires_at=8)
    with pytest.raises(SecurityError, match="expired"):
        mon.authorize_execution(ctx(epoch=9), token, "actuate")


# ---------------------------------------------------------------------------
# Single-use liveness (A4 replay)
# ---------------------------------------------------------------------------


def test_replay_of_consumed_nonce_raises() -> None:
    key = Ed25519PrivateKey.generate()
    mon = ABIDEExecutionBoundary(
        root_policy=set(ROOT), verifier=Ed25519Verifier(key.public_key()), audit=Recorder()
    )
    token = make_token(key)
    assert mon.authorize_execution(ctx(), token, "actuate") is True
    with pytest.raises(SecurityError, match="consumed"):
        mon.authorize_execution(ctx(), token, "actuate")


def test_fresh_nonce_after_replay_still_authorizes() -> None:
    key = Ed25519PrivateKey.generate()
    mon = ABIDEExecutionBoundary(
        root_policy=set(ROOT), verifier=Ed25519Verifier(key.public_key()), audit=Recorder()
    )
    assert mon.authorize_execution(ctx(), make_token(key, nonce="a"), "actuate")
    assert mon.authorize_execution(ctx(), make_token(key, nonce="b"), "actuate")


# ---------------------------------------------------------------------------
# Identity binding (A3 substitution)
# ---------------------------------------------------------------------------


def test_identity_substitution_raises() -> None:
    key = Ed25519PrivateKey.generate()
    mon = ABIDEExecutionBoundary(
        root_policy=set(ROOT), verifier=Ed25519Verifier(key.public_key()), audit=Recorder()
    )
    token = make_token(key, agent_id="victim-agent")
    stolen_ctx = ExecutionContext(
        agent_id="evil-agent",
        current_epoch=5,
        capabilities={"actuate"},
        root_policy=set(ROOT),
    )
    with pytest.raises(SecurityError, match="subject does not match"):
        mon.authorize_execution(stolen_ctx, token, "actuate")


# ---------------------------------------------------------------------------
# Capability lattice (A5 scope widening)
# ---------------------------------------------------------------------------


def test_context_capabilities_escape_p_root() -> None:
    key = Ed25519PrivateKey.generate()
    mon = ABIDEExecutionBoundary(
        root_policy=set(ROOT), verifier=Ed25519Verifier(key.public_key()), audit=Recorder()
    )
    token = make_token(key, capabilities=("actuate",))
    escaped = ctx(caps={"actuate", "rootkit"})
    with pytest.raises(SecurityError, match="escapes root policy"):
        mon.authorize_execution(escaped, token, "actuate")


def test_token_capabilities_exceed_session_context() -> None:
    key = Ed25519PrivateKey.generate()
    mon = ABIDEExecutionBoundary(
        root_policy=set(ROOT), verifier=Ed25519Verifier(key.public_key()), audit=Recorder()
    )
    token = make_token(key, capabilities=("actuate", "configure"))
    narrow = ctx(caps={"actuate"})
    with pytest.raises(SecurityError, match="session capabilities"):
        mon.authorize_execution(narrow, token, "actuate")


def test_action_outside_ai_is_denial_not_breach() -> None:
    key = Ed25519PrivateKey.generate()
    rec = Recorder()
    mon = ABIDEExecutionBoundary(
        root_policy=set(ROOT), verifier=Ed25519Verifier(key.public_key()), audit=rec
    )
    token = make_token(key, capabilities=("read",))
    c = ctx(caps={"read"})
    assert mon.authorize_execution(c, token, "actuate") is False
    assert "DENY" in rec.events()
    assert "SECURITY_BREACH" not in rec.events()


# ---------------------------------------------------------------------------
# Attenuation lattice
# ---------------------------------------------------------------------------


def test_attenuation_shrinks_and_derives_child_boundary() -> None:
    key = Ed25519PrivateKey.generate()
    parent = ABIDEExecutionBoundary(
        root_policy=set(ROOT), verifier=Ed25519Verifier(key.public_key()), audit=Recorder()
    )
    child = attenuating_boundary_for(parent, {"read"})
    assert child.root_policy == {"read"}
    token = make_token(key, capabilities=("read",))
    c = ExecutionContext(
        agent_id="agent-1", current_epoch=5,
        capabilities={"read"}, root_policy={"read"},
    )
    assert child.authorize_execution(c, token, "read") is True
    # actuate is outside the attenuated ceiling even though parent allowed it
    token2 = make_token(key, nonce="n-2", capabilities=("read",))
    assert child.authorize_execution(c, token2, "actuate") is False


def test_widening_attenuation_raises() -> None:
    parent = ABIDEExecutionBoundary(root_policy={"read"})
    with pytest.raises(SecurityError, match="violates lattice"):
        parent.attenuate({"read"}, {"read", "actuate"})


def test_child_shares_liveness_with_parent() -> None:
    key = Ed25519PrivateKey.generate()
    parent = ABIDEExecutionBoundary(
        root_policy=set(ROOT), verifier=Ed25519Verifier(key.public_key()), audit=Recorder()
    )
    child = attenuating_boundary_for(parent, {"actuate", "read"})
    token = make_token(key)
    c = ctx()
    assert child.authorize_execution(c, token, "actuate") is True
    # same nonce presented at the parent must now be treated as replay
    with pytest.raises(SecurityError, match="consumed"):
        parent.authorize_execution(c, token, "actuate")


# ---------------------------------------------------------------------------
# Legacy blueprint shape + quarantine hook
# ---------------------------------------------------------------------------


def test_legacy_blueprint_path_semantics() -> None:
    rec = Recorder()
    quarantined: list[str] = []
    mon = ABIDEExecutionBoundary(
        root_policy=set(ROOT), audit=rec, on_breach=quarantined.append
    )
    # authorized
    assert mon.authorize_and_dispatch(ctx(), "actuate", "legacy-nonce-1") is True
    # policy denial
    assert mon.authorize_and_dispatch(ctx(), "launch", "legacy-nonce-2") is False
    # replay breach -> raises + quarantine callback fires
    with pytest.raises(SecurityError, match="consumed"):
        mon.authorize_and_dispatch(ctx(), "actuate", "legacy-nonce-1")
    assert "boundary" in mon.quarantined
    assert quarantined == ["boundary"]


def test_legacy_capability_escape_raises() -> None:
    mon = ABIDEExecutionBoundary(root_policy=set(ROOT), audit=Recorder())
    escaped = ctx(caps={"actuate", "unlicensed"})
    with pytest.raises(SecurityError, match="Capability set escapes"):
        mon.authorize_and_dispatch(escaped, "actuate", "n-x")


def test_tampered_token_breaks_signature() -> None:
    """Epoch bump on a signed token changes canonical material -> sig fails."""
    key = Ed25519PrivateKey.generate()
    mon = ABIDEExecutionBoundary(
        root_policy=set(ROOT), verifier=Ed25519Verifier(key.public_key()), audit=Recorder()
    )
    honest = make_token(key, epoch=5)
    forged = replace(honest, epoch=6)  # frozen dataclass copy, re-signed? no: stale sig
    with pytest.raises(SecurityError, match="signature verification failed"):
        mon.authorize_execution(ctx(epoch=6), forged, "actuate")
