"""Tests for scripts/generate_dev_ledger_keys.py and the verify response schema.

Covers:
  * dev key generation (secret / pub.b64 / ed25519.key) and idempotent reuse;
  * whole-chain re-issuance producing chains that ledger_verifier.verify_chain
    accepts, with chain linkage rewritten against the new HMAC digests;
  * fail-closed refusal to write a chain that does not verify after re-issue;
  * the LedgerAPI.verify() error contract (Approach A): every failure verdict
    is HTTP 200 with an "errors" list -- including unknown audit IDs and
    unreadable ledgers -- while transport-level unavailability keeps 503 but
    still exposes the "errors" key.
"""
import base64
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ledger_verifier as lv  # noqa: E402
import scripts.ledger_api_server as srv  # noqa: E402
import scripts.generate_dev_ledger_keys as gdk  # noqa: E402

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key


@pytest.fixture()
def dev_dir(tmp_path, monkeypatch):
    root = str(tmp_path)
    monkeypatch.setattr(gdk, "_ROOT", root)
    d = os.path.join(root, ".ledgerdev")
    monkeypatch.setattr(gdk, "DEV_DIR", d)
    monkeypatch.setattr(gdk, "SECRET_FILE", os.path.join(d, "secret"))
    monkeypatch.setattr(gdk, "PUBKEY_FILE", os.path.join(d, "pub.b64"))
    monkeypatch.setattr(gdk, "PRIVATE_KEY_FILE", os.path.join(d, "ed25519.key"))
    return d


@pytest.fixture()
def sample_chain(tmp_path):
    """A minimal valid 2-entry chain signed with its own throwaway keys."""
    secret = b"x" * 32
    priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.urlsafe_b64encode(
        priv.public_key().public_bytes_raw()).decode("ascii")

    def entry(i, prev_hash, state):
        ctx = {"action": f"step_{i}", "target_cluster": "prod-a"}
        e = {
            "ledger_id": f"log_{i}",
            "workflow_id": "wf_test",
            "lifecycle_state": state,
            "timestamp": f"2026-10-1{i}T00:00:00Z",
            "previous_ledger_hash": prev_hash,
            "execution_context": ctx,
        }
        e["payload_hash"] = lv.compute_payload_hash(ctx)
        e["current_hash"] = lv.compute_current_hash(
            prev_hash, e["payload_hash"], e["timestamp"], secret)
        sig = priv.sign(e["current_hash"].encode())
        e["signature"] = "ed25519:" + base64.urlsafe_b64encode(sig).decode()
        return e

    approval = {
        "ledger_id": "log_0", "workflow_id": "wf_test",
        "lifecycle_state": "APPROVED", "timestamp": "2026-10-00T00:00:00Z",
        "previous_ledger_hash": lv._GENESIS_HASH,
        "execution_context": {"action": "approve"},
        "approval_context": {"authorized_targets": ["prod-a"]},
    }
    approval["payload_hash"] = lv.compute_payload_hash(
        approval["execution_context"])
    approval["current_hash"] = lv.compute_current_hash(
        approval["previous_ledger_hash"], approval["payload_hash"],
        approval["timestamp"], secret)
    sig = priv.sign(approval["current_hash"].encode())
    approval["signature"] = "ed25519:" + base64.urlsafe_b64encode(
        sig).decode()
    entries = [approval, entry(1, approval["current_hash"], "EXECUTING")]
    path = tmp_path / "chain.json"
    path.write_text(json.dumps(entries, indent=2))
    return str(path), secret, pub_b64


class TestKeyGeneration:
    def test_creates_all_three_files(self, dev_dir):
        secret, priv = gdk.ensure_keys(rotate=False)
        assert os.path.isfile(gdk.SECRET_FILE)
        assert os.path.isfile(gdk.PUBKEY_FILE)
        assert os.path.isfile(gdk.PRIVATE_KEY_FILE)
        assert len(secret) == 32
        with open(gdk.PUBKEY_FILE) as fh:
            stored_pub = fh.read().strip()
        actual = base64.urlsafe_b64encode(
            priv.public_key().public_bytes_raw()).decode()
        assert stored_pub == actual

    def test_reuses_existing_keys(self, dev_dir):
        s1, _ = gdk.ensure_keys(rotate=False)
        s2, _ = gdk.ensure_keys(rotate=False)
        assert s1 == s2

    def test_rotate_replaces_keys(self, dev_dir):
        s1, _ = gdk.ensure_keys(rotate=False)
        s2, _ = gdk.ensure_keys(rotate=True)
        assert s1 != s2

    def test_pubkey_mismatch_fails_closed(self, dev_dir):
        gdk.ensure_keys(rotate=False)
        with open(gdk.PUBKEY_FILE, "w") as fh:
            fh.write(base64.urlsafe_b64encode(b"\x00" * 32).decode())
        with pytest.raises(SystemExit):
            gdk.ensure_keys(rotate=False)


class TestReissue:
    def test_reissued_chain_verifies_with_new_keys(self, dev_dir, sample_chain):
        path, old_secret, old_pub = sample_chain
        secret, priv = gdk.ensure_keys(rotate=False)
        changed = gdk.reissue_ledger(path, secret, priv)
        assert changed is True
        entries = json.load(open(path))
        pub_b64 = base64.urlsafe_b64encode(
            priv.public_key().public_bytes_raw()).decode()
        assert lv.verify_chain(entries, secret, pub_b64) == []
        # Old key material must no longer verify anything.
        assert lv.verify_chain(entries, old_secret, old_pub) != []
        # Chain linkage was rewritten: entry 1 links to entry 0's NEW hash.
        assert entries[1]["previous_ledger_hash"] == entries[0]["current_hash"]

    def test_rerun_is_idempotent(self, dev_dir, sample_chain):
        path, _, _ = sample_chain
        secret, priv = gdk.ensure_keys(rotate=False)
        assert gdk.reissue_ledger(path, secret, priv) is True
        before = open(path).read()
        assert gdk.reissue_ledger(path, secret, priv) is False
        assert open(path).read() == before

    def test_refuses_unverifiable_chain(self, dev_dir, sample_chain, capsys):
        path, _, _ = sample_chain
        entries = json.load(open(path))
        # Break scope: EXECUTING targets something the APPROVAL never granted.
        entries[1]["execution_context"]["target_cluster"] = "shadow-prod"
        with open(path, "w") as fh:
            json.dump(entries, fh)
        secret, priv = gdk.ensure_keys(rotate=False)
        with pytest.raises(SystemExit) as exc:
            gdk.reissue_ledger(path, secret, priv)
        assert exc.value.code == 2
        assert "REFUSING" in capsys.readouterr().err
        # File untouched: still contains the tampered marker.
        assert "shadow-prod" in json.load(open(path))[1][
            "execution_context"]["target_cluster"]


class TestRepoLedgers:
    """The committed sample ledgers must verify under the real .ledgerdev keys."""

    @pytest.mark.parametrize("tenant,path", [
        ("acme", srv.LEDGER_FILE),
        ("tenant_abc123", os.path.join(
            srv._ROOT, "data", "ledgers", "export_job_9912.json")),
    ])
    def test_sample_ledgers_verify(self, tenant, path):
        secret, pubkey = srv._dev_keys()
        if secret is None:
            pytest.skip("dev key material not generated in this checkout")
        entries = json.load(open(path))
        assert lv.verify_chain(entries, secret, pubkey) == []


class TestVerifyResponseSchema:
    def test_unknown_audit_id_returns_errors_list(self, api=None):
        api = srv.LedgerAPI()
        status, body = api.verify("acme", {"auditId": "log_9999"})
        assert status == 200
        assert body["verified"] is False
        assert isinstance(body["errors"], list)
        assert any("not found" in e for e in body["errors"])

    def test_keys_unavailable_still_exposes_errors(self, tmp_path, monkeypatch):
        missing = tmp_path / "secret"
        monkeypatch.setattr(srv, "DEV_SECRET_FILE", str(missing))
        monkeypatch.setattr(srv, "DEV_PUBKEY_FILE", str(tmp_path / "pub.b64"))
        api = srv.LedgerAPI()
        status, body = api.verify("acme", {})
        assert status == 503
        assert body["verified"] is False
        assert any("verification_keys_unavailable" in e
                   for e in body["errors"])

    def test_ledger_read_failed_returns_errors_list(self, tmp_path, monkeypatch):
        bad = tmp_path / "broken.json"
        bad.write_text("{not json")
        monkeypatch.setattr(srv, "TENANT_LEDGER_FILES",
                            {**srv.TENANT_LEDGER_FILES, "acme": str(bad)})
        api = srv.LedgerAPI()
        status, body = api.verify("acme", {})
        assert status == 200
        assert body["verified"] is False
        assert any("ledger_read_failed" in e for e in body["errors"])
