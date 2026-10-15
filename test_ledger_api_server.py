"""Tests for scripts/ledger_api_server.py — the fail-closed processor API.

Covers the tx-1 incident end-to-end at the HTTP layer: overdraft rejection,
unit conventions, content-type strictness, idempotency, velocity throttling,
and audit-chain verification (including tamper detection).
"""
import json
import os
import sys
import threading
import time
from urllib import error as urlerror
from urllib import request as urlrequest

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scripts.ledger_api_server as srv  # noqa: E402


# ---------------------------------------------------------------- parse_route

@pytest.mark.parametrize("path", [
    "/api/v1/processors/acme/transactions",
    "/api/v1/processors/acme/verify",
])
def test_parse_route_canonical(path):
    tenant, resource = srv.parse_route(path)
    assert tenant == "acme"
    assert resource in ("transactions", "verify")


def test_parse_route_rejects_garbage():
    assert srv.parse_route("/healthz") is None
    assert srv.parse_route("/api/v1/other/acme/transactions") is None
    assert srv.parse_route("/evil/path") is None


# ------------------------------------------------------- LedgerAPI transactions

@pytest.fixture()
def api():
    return srv.LedgerAPI()


TX1 = {"id": "tx-1", "accountId": "cash", "amount": -150000,
       "description": "Big withdrawal"}


def test_tx1_overdraft_blocked(api):
    status, body = api.post_transaction("acme", dict(TX1))
    assert status == 402
    assert body["verdict"] == "OVERDRAFT_BLOCKED"
    assert body["balance_after_cents"] == -50000
    # Blocked actions must never consume velocity budget.
    assert body["velocity_admission"] == "NOT_ATTEMPTED"
    assert api.redis.zcard("velocity:processor:acme") == 0


def test_tx1_requires_dual_approval_even_if_balance_ok(api):
    # risk floor: any outgoing movement is authz-impacting -> dual_approval
    status, body = api.post_transaction("acme", {
        "id": "tx-debit", "accountId": "cash", "amount": -1000})
    assert status == 202
    assert body["approval_policy_required"] == "dual_approval"


def test_balance_safe_held_for_approval(api):
    status, body = api.post_transaction("acme", {
        "id": "tx-3", "accountId": "cash", "amount": -40000,
        "description": "Small withdrawal"})
    assert status == 202
    assert body["verdict"] == "BALANCE_SAFE"
    assert body["state"] == "PROPOSED_AWAITING_APPROVAL"
    assert body["balance_after_cents"] == 60000
    # admitted action recorded in the velocity window
    assert api.redis.zcard("velocity:processor:acme") == 1


def test_minor_major_unit_conversions(api):
    # major: $400 = 40000 cents, same effect as minor 40000
    _, b_major = api.post_transaction("acme", {
        "id": "tx-maj", "accountId": "cash", "amount": -400, "unit": "major"})
    _, b_minor = api.post_transaction("acme", {
        "id": "tx-min", "accountId": "cash", "amount": -40000, "unit": "minor"})
    assert b_major["delta_cents"] == b_minor["delta_cents"] == -40000
    assert b_major["balance_after_cents"] == b_minor["balance_after_cents"]


def test_major_non_whole_dollar_rejected(api):
    status, body = api.post_transaction("acme", {
        "id": "tx-frac", "accountId": "cash", "amount": 10.5, "unit": "major"})
    assert status == 400
    assert body["error"] == "amount_not_exact_in_cents"


def test_unknown_account_fails_closed(api):
    status, body = api.post_transaction("acme", {
        "id": "tx-x", "accountId": "savings", "amount": -1})
    assert status == 404
    assert body["error"] == "account_not_in_anchored_snapshot"


def test_unknown_tenant_fails_closed(api):
    status, body = api.post_transaction("globex", dict(TX1))
    assert status == 404
    assert body["error"] == "unknown_tenant"


def test_validation_rejects_bad_payloads(api):
    bad = [
        ({}, "missing_or_invalid_id"),
        ({"id": "a"}, "missing_or_invalid_accountId"),
        ({"id": "a", "accountId": "cash"}, "amount_must_be_numeric"),
        ({"id": "a", "accountId": "cash", "amount": True},
         "amount_must_be_numeric"),
        ({"id": "a", "accountId": "cash", "amount": 1, "unit": "dollars"},
         "unit_must_be_major_or_minor"),
        ({"id": "a", "accountId": "cash", "amount": 1, "extra": 1},
         "unexpected_fields"),
    ]
    for payload, err in bad:
        status, body = api.post_transaction("acme", payload)
        assert status == 400, payload
        assert body["error"] == err, payload


def test_idempotent_duplicate_returns_cached_verdict(api):
    s1, b1 = api.post_transaction("acme", dict(TX1))
    s2, b2 = api.post_transaction("acme", dict(TX1))
    assert (s1, s2) == (402, 402)
    assert b2["duplicate"] is True
    assert b1["tx_payload_hash"] == b2["tx_payload_hash"]


def test_velocity_throttle_after_budget_exhausted(api):
    # Debits floor at effective risk 60 (authz) -> only 1 fits per 100 budget.
    s1, b1 = api.post_transaction("acme", {
        "id": "vtx-0", "accountId": "cash", "amount": -1})
    assert s1 == 202 and b1["velocity_cost"] == 60
    s2, b2 = api.post_transaction("acme", {
        "id": "vtx-1", "accountId": "cash", "amount": -1})
    assert s2 == 429
    assert b2["error"] == "velocity_exceeded"
    # blocked action was NOT recorded
    assert api.redis.zcard("velocity:processor:acme") == 1


# ------------------------------------------------------------- verify endpoint

def test_verify_chain_passes(api):
    status, body = api.verify("acme", {})
    assert status == 200
    assert body["verified"] is True, body.get("errors")


def test_verify_expected_hash_mismatch(api):
    status, body = api.verify("acme", {
        "auditId": "log_4492", "expectedHash": "sha256:deadbeef"})
    assert status == 200
    assert body["verified"] is False
    assert any("expectedHash mismatch" in e for e in body["errors"])


def test_verify_unknown_audit_id(api):
    status, body = api.verify("acme", {"auditId": "log_9999"})
    assert body["verified"] is False
    assert any("not found" in e for e in body["errors"])


def test_verify_detects_tampered_ledger(tmp_path, monkeypatch):
    chain = json.load(open(srv.LEDGER_FILE))
    chain[0]["execution_context"]["accounts"][0]["balance"]["amount"] = 1
    tampered = tmp_path / "wf_992.json"
    tampered.write_text(json.dumps(chain))
    monkeypatch.setattr(srv, "LEDGER_FILE", str(tampered))
    api = srv.LedgerAPI()
    status, body = api.verify("acme", {})
    assert status == 200
    assert body["verified"] is False
    assert any("payload_hash mismatch" in e for e in body["errors"])


def test_transactions_refuse_unverifiable_anchor(tmp_path, monkeypatch, api):
    chain = json.load(open(srv.LEDGER_FILE))
    chain[0]["payload_hash"] = "sha256:" + "0" * 64  # tamper
    bad = tmp_path / "wf_992.json"
    bad.write_text(json.dumps(chain))
    monkeypatch.setattr(srv, "LEDGER_FILE", str(bad))
    fresh = srv.LedgerAPI()
    status, body = fresh.post_transaction("acme", dict(TX1))
    assert status == 503
    assert body["error"] == "anchor_snapshot_unverifiable"


# ------------------------------------------------------------ HTTP integration

@pytest.fixture(scope="module")
def live_server():
    """Boot the real server on an ephemeral port for one module."""
    from http.server import ThreadingHTTPServer
    old_port = os.environ.get("PORT")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    if old_port is not None:
        os.environ["PORT"] = old_port


def _post(url, data, ctype=None):
    req = urlrequest.Request(url, data=data.encode(), method="POST")
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urlrequest.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urlerror.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_http_exact_user_curl_gets_415(live_server):
    # curl's default Content-Type is form-urlencoded -> strict JSON endpoint
    url = live_server + "/api/v1/processors/acme/transactions"
    status, body = _post(url, json.dumps(TX1),
                         "application/x-www-form-urlencoded")
    assert status == 415
    assert "hint" in body


def test_http_tx1_overdraft_roundtrip(live_server):
    url = live_server + "/api/v1/processors/acme/transactions"
    status, body = _post(url, json.dumps(TX1), "application/json")
    assert status == 402
    assert body["verdict"] == "OVERDRAFT_BLOCKED"
    assert body["balance_after_cents"] == -50000


def test_http_malformed_json_body_400(live_server):
    url = live_server + "/api/v1/processors/acme/transactions"
    status, body = _post(url, "{not json", "application/json")
    assert status == 400
    assert body["error"] == "malformed_json_body"


def test_http_array_body_rejected(live_server):
    url = live_server + "/api/v1/processors/acme/transactions"
    status, body = _post(url, "[1,2,3]", "application/json")
    assert status == 400
    assert body["error"] == "malformed_json_body"


def test_http_unknown_route_404(live_server):
    status, body = _post(live_server + "/api/v1/processors/acme/nope",
                         "{}", "application/json")
    assert status == 404
