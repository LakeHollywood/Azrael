"""Tests for the structured, hash-chained audit log (audit_log.py) and its
integration into the ledger API server."""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import audit_log
from audit_log import AuditLogger, compute_entry_hash, verify_chain


@pytest.fixture()
def log_path(tmp_path):
    return str(tmp_path / "audit.jsonl")


def read_records(path):
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


class TestRecordShape:
    def test_record_has_required_structured_fields(self, log_path):
        logger = AuditLogger(log_path)
        rec = logger.log_event("tx.proposed", tenant="acme", actor="operator",
                               outcome="proposed", resource="transactions",
                               details={"tx_id": "tx_1"})
        assert rec is not None
        for field in ("ts", "seq", "event_type", "actor", "outcome",
                      "prev_hash", "entry_hash", "tenant", "resource",
                      "details"):
            assert field in rec, f"missing {field}"
        assert rec["seq"] == 1
        assert rec["prev_hash"] == audit_log.GENESIS_HASH

    def test_one_json_object_per_line(self, log_path):
        logger = AuditLogger(log_path)
        logger.log_event("a")
        logger.log_event("b")
        with open(log_path, "r", encoding="utf-8") as fh:
            lines = [ln for ln in fh if ln.strip()]
        assert len(lines) == 2
        for ln in lines:
            assert isinstance(json.loads(ln), dict)

    def test_seq_increments_and_chain_links(self, log_path):
        logger = AuditLogger(log_path)
        r1 = logger.log_event("a")
        r2 = logger.log_event("b")
        r3 = logger.log_event("c")
        assert [r1["seq"], r2["seq"], r3["seq"]] == [1, 2, 3]
        assert r2["prev_hash"] == r1["entry_hash"]
        assert r3["prev_hash"] == r2["entry_hash"]

    def test_entry_hash_covers_all_other_fields(self, log_path):
        logger = AuditLogger(log_path)
        rec = logger.log_event("a", details={"k": "v"})
        assert rec["entry_hash"] == compute_entry_hash(rec)
        tampered = dict(rec, details={"k": "tampered"})
        assert compute_entry_hash(tampered) != rec["entry_hash"]


class TestPersistenceAcrossInstances:
    def test_new_instance_continues_the_chain(self, log_path):
        AuditLogger(log_path).log_event("a")
        second = AuditLogger(log_path)
        rec = second.log_event("b")
        assert rec["seq"] == 2
        ok, errs = verify_chain(log_path)
        assert ok, errs

    def test_torn_final_line_is_tolerated(self, log_path):
        first = AuditLogger(log_path)
        r1 = first.log_event("a")
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write('{"seq": 2, partial\n')  # crash-mid-write garbage
        second = AuditLogger(log_path)
        r2 = second.log_event("b")
        # Recovers lineage from last VALID record (the torn line is ignored
        # by tail recovery; seq restarts after genesis-linked state).
        assert r2["prev_hash"] in (r1["entry_hash"], audit_log.GENESIS_HASH)


class TestVerifyChain:
    def test_clean_chain_verifies(self, log_path):
        logger = AuditLogger(log_path)
        for i in range(5):
            logger.log_event(f"event.{i}")
        ok, errs = verify_chain(log_path)
        assert ok, errs

    def test_detects_edited_field(self, log_path):
        logger = AuditLogger(log_path)
        logger.log_event("a")
        rec_b = logger.log_event("b", details={"amount": 100})
        logger.log_event("c")
        records = read_records(log_path)
        # Tamper: change the amount inside record 2's details.
        for r in records:
            if r["seq"] == rec_b["seq"]:
                r["details"]["amount"] = 999999
        with open(log_path, "w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r) + "\n")
        ok, errs = verify_chain(log_path)
        assert not ok
        assert any("entry_hash mismatch" in e for e in errs)

    def test_detects_deleted_record(self, log_path):
        logger = AuditLogger(log_path)
        for i in range(4):
            logger.log_event(f"e{i}")
        records = read_records(log_path)
        del records[1]  # remove the second entry
        with open(log_path, "w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r) + "\n")
        ok, errs = verify_chain(log_path)
        assert not ok
        assert any("chain break" in e or "not contiguous" in e for e in errs)

    def test_empty_file_reports_no_records(self, tmp_path):
        path = str(tmp_path / "empty.jsonl")
        open(path, "w").close()
        ok, errs = verify_chain(path)
        assert not ok
        assert "no records found" in errs


class TestFailureModes:
    def test_write_failure_returns_none_by_default(self, tmp_path, capsys):
        blocker = tmp_path / "blocker"
        blocker.mkdir()  # a directory where the log file should live
        logger = AuditLogger(str(blocker))
        assert logger.log_event("a") is None
        assert "FAILED to write" in capsys.readouterr().err

    def test_write_failure_raises_when_strict(self, tmp_path):
        blocker = tmp_path / "blocker"
        blocker.mkdir()
        logger = AuditLogger(str(blocker))
        with pytest.raises(RuntimeError):
            logger.log_event("a", strict=True)


class TestLedgerApiIntegration:
    """The ledger API must emit audit records for security-relevant calls."""

    def _fresh_api(self, monkeypatch, tmp_path):
        path = str(tmp_path / "api-audit.jsonl")
        monkeypatch.setenv("AUDIT_LOG_FILE", path)
        audit_log.reset_logger()
        import scripts.ledger_api_server as srv
        # Full constructor: with agent/task separation the LedgerAPI AGENT
        # (identity, task registry, audit wiring) is built in __init__, so
        # bypassing it would leave request execution without a task boundary.
        return srv.LedgerAPI(), path

    def test_unknown_tenant_is_audited(self, monkeypatch, tmp_path):
        api, path = self._fresh_api(monkeypatch, tmp_path)
        status, payload = api.post_transaction("nope", {})
        assert status == 404
        records = read_records(path)
        assert any(r["event_type"] == "tx.rejected"
                   and r["tenant"] == "nope" for r in records)
        ok, errs = verify_chain(path)
        assert ok, errs

    def test_proposed_transaction_writes_chained_audit_record(
            self, monkeypatch, tmp_path):
        api, path = self._fresh_api(monkeypatch, tmp_path)
        status, payload = api.post_transaction("acme", {
            "id": "tx-audit-ok", "accountId": "cash", "amount": -1000,
            "description": "operator-7"})
        assert status == 202, payload
        records = read_records(path)
        tx_recs = [r for r in records if r["event_type"] == "tx.proposed"]
        assert len(tx_recs) == 1
        rec = tx_recs[0]
        assert rec["tenant"] == "acme"
        assert rec["actor"] == "system"  # no actor header supplied
        assert rec["details"]["description"] == "operator-7"
        details = rec["details"]
        assert details["tx_id"] == "tx-audit-ok"
        assert details["approval_policy"] == "dual_approval"
        assert details["effective_risk_score"] >= 60
        # The approval record's policy must match the API's own verdict.
        assert details["approval_policy"] == payload["approval_policy_required"]
        ok, errs = verify_chain(path)
        assert ok, errs

    def test_overdraft_block_is_audited(self, monkeypatch, tmp_path):
        api, path = self._fresh_api(monkeypatch, tmp_path)
        status, payload = api.post_transaction("acme", {
            "id": "tx-audit-bad", "accountId": "cash", "amount": -150000,
            "description": "Big withdrawal"})
        assert status == 402, payload
        records = read_records(path)
        blocked = [r for r in records
                   if r["event_type"] == "tx.overdraft_blocked"]
        assert len(blocked) == 1
        assert blocked[0]["outcome"] == "blocked"
        assert blocked[0]["details"]["tx_id"] == "tx-audit-bad"
        ok, errs = verify_chain(path)
        assert ok, errs

    def test_duplicate_submission_is_audited(self, monkeypatch, tmp_path):
        api, path = self._fresh_api(monkeypatch, tmp_path)
        body = {"id": "tx-dup", "accountId": "cash", "amount": -1000}
        assert api.post_transaction("acme", dict(body))[0] == 202
        status, payload = api.post_transaction("acme", dict(body))
        assert status == 202 and payload.get("duplicate") is True
        records = read_records(path)
        assert any(r["event_type"] == "tx.duplicate" for r in records)
        ok, errs = verify_chain(path)
        assert ok, errs

    def test_verify_outcome_is_audited(self, monkeypatch, tmp_path):
        api, path = self._fresh_api(monkeypatch, tmp_path)
        status, payload = api.verify("acme", {})
        records = read_records(path)
        kinds = {r["event_type"] for r in records}
        assert status in (200, 503)
        if status == 200:
            assert kinds & {"verify.chain_passed", "verify.chain_failed"}
        else:
            assert "verify.unavailable" in kinds
        ok, errs = verify_chain(path)
        assert ok, errs
