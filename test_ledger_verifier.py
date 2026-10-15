"""Tests for ledger_verifier: cryptographic chain verification + scope checks.

Covers the wf_992 remediation requirements:
  * full digests / strict JSON (fail closed on truncation & comments)
  * canonical payload hashing, HMAC canonicalization, real ed25519 signatures
  * APPROVED predecessor must enumerate authorized_targets; out-of-scope
    execution (e.g. prod-us-east-1 under a staging approval) is rejected
  * CLI entry point used by the CI compliance gate exits non-zero on failure
"""

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption)

import ledger_verifier as lv

SECRET = b"test-hmac-secret-32byteslong!!"
_PRIVKEY = Ed25519PrivateKey.generate()
PUB_B64 = base64.urlsafe_b64encode(_PRIVKEY.public_key().public_bytes_raw()).decode()


def _sign(current_hash: str) -> str:
    return "ed25519:" + base64.urlsafe_b64encode(
        _PRIVKEY.sign(current_hash.encode("utf-8"))).decode()


def make_entry(ledger_id, state, context, prev_hash, timestamp,
               authorized_targets=None):
    """Build a fully valid signed entry (optionally an APPROVAL_CONTEXT for
    APPROVED entries)."""
    entry = {
        "ledger_id": ledger_id,
        "workflow_id": "wf_992",
        "lifecycle_state": state,
        "timestamp": timestamp,
        "previous_ledger_hash": prev_hash,
        "execution_context": context,
    }
    if state == "APPROVED" and authorized_targets is not None:
        entry["approval_context"] = {"authorized_targets": authorized_targets}
    entry["payload_hash"] = lv.compute_payload_hash(context)
    entry["current_hash"] = lv.compute_current_hash(
        prev_hash, entry["payload_hash"], timestamp, SECRET)
    entry["signature"] = _sign(entry["current_hash"])
    return entry


GENESIS = lv._GENESIS_HASH

PROPOSED = make_entry(
    "log_4489", "PROPOSED",
    {"tool_name": "propose_batch", "batch_id": "batch_882"},
    GENESIS, "2026-10-15T14:30:00Z")

APPROVED_STAGING = make_entry(
    "log_4490", "APPROVED",
    {"tool_name": "approval_grant", "batch_id": "batch_882"},
    PROPOSED["current_hash"], "2026-10-15T14:31:00Z",
    authorized_targets=["staging-gw-01", "staging-gw-02"])

EXEC_OK = make_entry(
    "log_4491", "EXECUTING",
    {"tool_name": "kubernetes_deploy", "target_cluster": "staging-gw-01",
     "manifest_hash": "sha256:" + "a1" * 32},
    APPROVED_STAGING["current_hash"], "2026-10-15T14:32:01Z")

EXEC_PROD = make_entry(
    "log_4491", "EXECUTING",
    {"tool_name": "kubernetes_deploy", "target_cluster": "prod-us-east-1",
     "manifest_hash": "sha256:" + "a1" * 32},
    APPROVED_STAGING["current_hash"], "2026-10-15T14:32:01Z")


# ---------------------------------------------------------------- happy paths

class TestValidEntries:
    def test_valid_chain_passes(self):
        assert lv.verify_chain([PROPOSED, APPROVED_STAGING, EXEC_OK],
                               SECRET, PUB_B64) == []

    def test_valid_single_entry_with_predecessor(self):
        assert lv.verify_entry(EXEC_OK, SECRET, PUB_B64,
                               expected_previous_state_entry=APPROVED_STAGING) == []

    def test_extract_targets_covers_all_target_keys(self):
        ctx = {"target_cluster": "c1", "target_gateways": ["g1", "g2"],
               "tool_name": "x"}
        assert lv.extract_targets(ctx) == ["c1", "g1", "g2"]


# ------------------------------------------------------- fail-closed negatives

class TestTamperingFailsClosed:
    def test_truncated_digest_rejected(self):
        bad = dict(EXEC_OK, previous_ledger_hash="sha256:8f7d...")
        errs = lv.verify_entry(bad, SECRET, PUB_B64, APPROVED_STAGING)
        assert any("full sha256" in e for e in errs)

    def test_non_hex_digest_rejected(self):
        bad = dict(EXEC_OK, current_hash="sha256:" + "z" * 64)
        errs = lv.verify_entry(bad, SECRET, PUB_B64, APPROVED_STAGING)
        assert any("full sha256" in e for e in errs)

    def test_missing_field_rejected(self):
        bad = {k: v for k, v in EXEC_OK.items() if k != "signature"}
        errs = lv.verify_entry(bad, SECRET, PUB_B64, APPROVED_STAGING)
        assert any("missing field: signature" in e for e in errs)

    def test_wrong_hmac_secret_rejected(self):
        errs = lv.verify_entry(EXEC_OK, b"attacker-secret", PUB_B64,
                               APPROVED_STAGING)
        assert any("HMAC mismatch" in e for e in errs)

    def test_wrong_pubkey_rejected(self):
        other = base64.urlsafe_b64encode(
            Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode()
        errs = lv.verify_entry(EXEC_OK, SECRET, other, APPROVED_STAGING)
        assert any("ed25519 signature invalid" in e for e in errs)

    def test_signature_over_wrong_scheme_rejected(self):
        bad = dict(EXEC_OK, signature="hmac:deadbeef")
        errs = lv.verify_entry(bad, SECRET, PUB_B64, APPROVED_STAGING)
        assert any("ed25519:' scheme" in e for e in errs)

    def test_payload_tampering_detected(self):
        tampered = json.loads(json.dumps(EXEC_OK))
        tampered["execution_context"]["manifest_hash"] = "sha256:" + "ff" * 32
        errs = lv.verify_entry(tampered, SECRET, PUB_B64, APPROVED_STAGING)
        assert any("payload_hash mismatch" in e for e in errs)

    def test_canonical_json_is_order_independent(self):
        a = lv.compute_payload_hash({"b": 1, "a": 2})
        b = lv.compute_payload_hash({"a": 2, "b": 1})
        assert a == b

    def test_illegal_transition_rejected(self):
        # EXECUTING cannot follow EXECUTING.
        second_exec = make_entry("log_x", "EXECUTING",
                                 {"tool_name": "t", "target_cluster": "staging-gw-01"},
                                 EXEC_OK["current_hash"], "2026-10-15T14:33:00Z")
        errs = lv.verify_entry(second_exec, SECRET, PUB_B64,
                               expected_previous_state_entry=EXEC_OK)
        assert any("illegal transition EXECUTING -> EXECUTING" in e for e in errs)

    def test_chain_break_rejected(self):
        forged_prev = "sha256:" + "b" * 64
        orphan = dict(EXEC_OK, previous_ledger_hash=forged_prev)
        errs = lv.verify_entry(orphan, SECRET, PUB_B64, APPROVED_STAGING)
        assert any("chain break" in e or "does not match" in e for e in errs)

    def test_verify_chain_detects_middle_tampering(self):
        broken = [PROPOSED, dict(APPROVED_STAGING,
                                 execution_context={"tool_name": "evil"}),
                  EXEC_OK]
        errs = lv.verify_chain(broken, SECRET, PUB_B64)
        assert errs and errs[0].startswith("[1:log_4490]")


# ------------------------------------------------------------ scope enforcement

class TestApprovalScope:
    def test_out_of_scope_target_rejected(self):
        """The exact wf_992/log_4491 violation: prod deploy under a
        staging-only approval."""
        errs = lv.verify_entry(EXEC_PROD, SECRET, PUB_B64, APPROVED_STAGING)
        assert any("outside approved scope" in e and "prod-us-east-1" in e
                   for e in errs)

    def test_approved_entry_without_targets_fails_closed(self):
        no_scope = make_entry("log_ns", "APPROVED",
                              {"tool_name": "approval_grant"},
                              PROPOSED["current_hash"], "2026-10-15T14:31:00Z")
        exec_after = make_entry("log_ns2", "EXECUTING",
                                {"tool_name": "kubernetes_deploy",
                                 "target_cluster": "anywhere"},
                                no_scope["current_hash"], "2026-10-15T14:32:00Z")
        errs = lv.verify_entry(exec_after, SECRET, PUB_B64,
                               expected_previous_state_entry=no_scope)
        assert any("lacks a non-empty" in e for e in errs)

    def test_empty_targets_list_fails_closed(self):
        empty = make_entry("log_e", "APPROVED", {"tool_name": "approval_grant"},
                           PROPOSED["current_hash"], "2026-10-15T14:31:00Z",
                           authorized_targets=[])
        errs = lv.verify_entry(EXEC_OK, SECRET, PUB_B64,
                               expected_previous_state_entry=empty)
        assert any("lacks a non-empty" in e for e in errs)

    def test_multi_target_approval_admits_each(self):
        ok2 = make_entry("log_ok2", "EXECUTING",
                         {"tool_name": "kubernetes_deploy",
                          "target_cluster": "staging-gw-02"},
                         APPROVED_STAGING["current_hash"], "2026-10-15T14:32:02Z")
        assert lv.verify_entry(ok2, SECRET, PUB_B64, APPROVED_STAGING) == []


# ------------------------------------------------------------------ CLI / gate

class TestCli:
    def _write(self, tmp_path, chain):
        p = tmp_path / "ledger.json"
        p.write_text(json.dumps(chain))
        secret_file = tmp_path / "secret"
        secret_file.write_bytes(SECRET)
        key_file = tmp_path / "key.pem"
        # PEM format so scripts/reissue_ledger_entry.py can load it directly.
        key_file.write_bytes(
            _PRIVKEY.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH,
                                   NoEncryption()))
        return str(p), str(secret_file), str(key_file)

    def test_cli_passes_valid_chain(self, tmp_path, capsys):
        ledger, secret_file, _ = self._write(
            tmp_path, [PROPOSED, APPROVED_STAGING, EXEC_OK])
        rc = lv.main(["verify-ledger", "--ledger", ledger,
                      "--hmac-secret-file", secret_file,
                      "--pubkey-b64", PUB_B64])
        assert rc == 0
        assert "passed" in capsys.readouterr().out

    def test_cli_fails_on_prod_scope_violation(self, tmp_path, capsys):
        ledger, secret_file, _ = self._write(
            tmp_path, [PROPOSED, APPROVED_STAGING, EXEC_PROD])
        rc = lv.main(["verify-ledger", "--ledger", ledger,
                      "--entry-id", "log_4491",
                      "--hmac-secret-file", secret_file,
                      "--pubkey-b64", PUB_B64])
        assert rc == 1
        err = capsys.readouterr().err
        assert "outside approved scope" in err and "prod-us-east-1" in err

    def test_cli_strict_json_rejects_comments(self, tmp_path):
        p = tmp_path / "ledger.json"
        p.write_text('[ // THE CHAIN\n {"ledger_id": "x"} ]')
        rc = lv.main(["verify-ledger", "--ledger", str(p),
                      "--hmac-secret-b64", base64.b64encode(SECRET).decode(),
                      "--pubkey-b64", PUB_B64])
        assert rc == 2  # input error, fail closed

    def test_cli_missing_entry_id_fails(self, tmp_path, capsys):
        ledger, secret_file, _ = self._write(tmp_path, [PROPOSED])
        rc = lv.main(["verify-ledger", "--ledger", ledger,
                      "--entry-id", "log_9999",
                      "--hmac-secret-file", secret_file,
                      "--pubkey-b64", PUB_B64])
        assert rc == 1
        assert "not found" in capsys.readouterr().err


# ------------------------------------------------- re-issue script (anchoring)

import importlib.util as _ilu
_spec = _ilu.spec_from_file_location(
    "reissue_ledger_entry",
    __file__.rsplit("/", 1)[0] + "/scripts/reissue_ledger_entry.py")
reissue = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(reissue)

from cryptography.hazmat.primitives.serialization import (
    Encoding as _Enc, PrivateFormat as _PF, NoEncryption as _NE)

_PKCS8_KEY = _PRIVKEY.private_bytes(_Enc.PEM, _PF.PKCS8, _NE())

SNAPSHOT = {
    "tenantId": "acme",
    "accounts": [{"id": "cash", "type": "asset",
                  "balance": {"amount": 100000, "currency": "USD"}}],
}
SNAPSHOT_HASH = lv.compute_payload_hash(SNAPSHOT)


def _proposed_draft():
    return {
        "ledger_id": "log_4492",
        "workflow_id": "wf_992",
        "lifecycle_state": "PROPOSED",
        "timestamp": "2026-10-15T14:35:00Z",
        "previous_ledger_hash": GENESIS,
        "execution_context": SNAPSHOT,
    }


class TestReissueAnchoring:
    def _files(self, tmp_path, draft, snapshot=None):
        d = tmp_path / "draft.json"
        d.write_text(json.dumps(draft))
        led = tmp_path / "ledger.json"
        led.write_text("[]")
        sec = tmp_path / "secret"
        sec.write_bytes(SECRET)
        key = tmp_path / "key.pem"
        key.write_bytes(_PKCS8_KEY)
        snap = None
        if snapshot is not None:
            snap = tmp_path / "snap.json"
            snap.write_text(json.dumps(snapshot))
        return str(d), str(led), str(sec), str(key), str(snap) if snap else None

    def _run(self, tmp_path, draft, payload_hash=None, snapshot=None):
        d, led, sec, key, snap = self._files(tmp_path, draft, snapshot)
        argv = ["--draft", d, "--ledger", led, "--hmac-secret-file", sec,
                "--signing-key-file", key, "--out", str(tmp_path / "out.json")]
        if payload_hash:
            argv += ["--payload-hash", payload_hash]
        if snap:
            argv += ["--snapshot-file", snap]
        return reissue.main(argv)

    def test_proposed_genesis_link_accepted(self, tmp_path):
        assert self._run(tmp_path, _proposed_draft()) == 0
        chain = json.loads((tmp_path / "out.json").read_text())
        assert len(chain) == 1 and chain[0]["ledger_id"] == "log_4492"
        # entry verifies independently after being written
        assert lv.verify_chain(chain, SECRET, PUB_B64) == []

    def test_snapshot_anchor_sets_declared_payload_hash(self, tmp_path):
        rc = self._run(tmp_path, _proposed_draft(),
                       payload_hash=SNAPSHOT_HASH, snapshot=SNAPSHOT)
        assert rc == 0
        entry = json.loads((tmp_path / "out.json").read_text())[0]
        assert entry["payload_hash"] == SNAPSHOT_HASH
        assert lv.verify_chain([entry], SECRET, PUB_B64) == []

    def test_mismatched_pinned_hash_fails_closed(self, tmp_path):
        bogus = "sha256:" + "3c4e" + "0" * 60
        assert self._run(tmp_path, _proposed_draft(),
                         payload_hash=bogus, snapshot=SNAPSHOT) == 2
        assert not (tmp_path / "out.json").exists()

    def test_truncated_pinned_hash_fails_closed(self, tmp_path):
        assert self._run(tmp_path, _proposed_draft(),
                         payload_hash="sha256:fe41...") == 2

    def test_executing_cannot_link_genesis(self, tmp_path):
        draft = _proposed_draft()
        draft["lifecycle_state"] = "EXECUTING"
        assert self._run(tmp_path, draft) == 2

    def test_executing_requires_approved_predecessor(self, tmp_path):
        # Predecessor in ledger is PROPOSED, not APPROVED -> refuse.
        d = tmp_path / "draft.json"
        prop = make_entry("log_p", "PROPOSED", {"tool_name": "t"},
                          GENESIS, "2026-10-15T14:00:00Z")
        exec_draft = {"ledger_id": "log_e", "workflow_id": "wf_992",
                      "lifecycle_state": "EXECUTING",
                      "timestamp": "2026-10-15T14:01:00Z",
                      "previous_ledger_hash": prop["current_hash"],
                      "execution_context": {"tool_name": "kubernetes_deploy",
                                            "target_cluster": "staging-gw-01"}}
        d.write_text(json.dumps(exec_draft))
        led = tmp_path / "ledger.json"
        led.write_text(json.dumps([prop]))
        sec = tmp_path / "secret"; sec.write_bytes(SECRET)
        key = tmp_path / "key.pem"; key.write_bytes(_PKCS8_KEY)
        rc = reissue.main(["--draft", str(d), "--ledger", str(led),
                           "--hmac-secret-file", str(sec),
                           "--signing-key-file", str(key),
                           "--out", str(tmp_path / "out.json")])
        assert rc == 2

    def test_sign_entry_rejects_unanchorable_pin(self):
        draft = _proposed_draft()
        with pytest.raises(ValueError, match="fail closed"):
            reissue.sign_entry(draft, SECRET, _PRIVKEY,
                               "sha256:" + "e" * 64)
