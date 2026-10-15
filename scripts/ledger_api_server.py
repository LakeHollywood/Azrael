#!/usr/bin/env python3
"""Fail-closed ledger API server (localhost:3000).

Exposes the same pre-execution controls as the CI gate, but at request time:

  POST /api/v1/processors/<tenant>/transactions
      -> balance safety check anchored to the signed snapshot in
         data/ledgers/wf_992.json (OVERDRAFT_BLOCKED => 402)
      -> approval-policy determination (dual_approval floor for authz-impacting
         movements)
      -> velocity admission via VelocityMonitor.check_and_record_atomic()

  POST /api/v1/processors/<tenant>/verify
      -> audit-chain verification (payload-hash recomputation + chain walk)

  GET  /healthz

Design notes:
  * Money is integer minor units (cents) everywhere — the anchored snapshot
    stores cash=100000 meaning $1,000.00. Transaction amounts default to
    minor units ("unit":"major" opts into whole dollars, converted exactly).
    No float arithmetic on balances; overdraft check is cent-accurate.
  * Unknown tenants/accounts fail closed.
  * Redis: uses fakeredis when REDIS_URL is unset or unreachable, so the
    throttle works locally; production should point at real Redis.
"""

from __future__ import annotations

import json
import sys
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ledger_verifier as lv  # noqa: E402
from approval_gate.risk import determine_policy, apply_overrides  # noqa: E402
from velocity_monitor import VelocityMonitor  # noqa: E402
from scripts.balance_safety_check import balances_from_snapshot  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER_FILE = os.path.join(_ROOT, "data", "ledgers", "wf_992.json")
# Tenant -> ledger file for whole-chain verification via POST /verify.
# Tenants absent from this map cannot be verified (fail closed).
TENANT_LEDGER_FILES = {
    "acme": LEDGER_FILE,
    "tenant_abc123": os.path.join(_ROOT, "data", "ledgers",
                                  "export_job_9912.json"),
}
ANCHOR_ENTRY_ID = "log_4492"
DEV_SECRET_FILE = os.path.join(_ROOT, ".ledgerdev", "secret")
DEV_PUBKEY_FILE = os.path.join(_ROOT, ".ledgerdev", "pub.b64")

VALID_TX_FIELDS = {"id", "accountId", "amount", "description", "unit"}
# Guard against float64-exactness overflow on absurd magnitudes.
MAX_DELTA_CENTS = 2 ** 53


def parse_route(path: str):
    """Return (tenant, resource) for /api/v1/processors/<tenant>/<resource>, else None."""
    parts = [p for p in path.split("?")[0].split("/") if p]
    # canonical: ['api','v1','processors',tenant,resource] -> len 5
    # tolerate versionless: ['api','processors',tenant,resource] -> len 4
    if len(parts) == 5 and parts[0] == "api" and parts[2] == "processors":
        return parts[3], parts[4]
    if len(parts) == 4 and parts[0] == "api" and parts[1] == "processors":
        return parts[2], parts[3]
    return None


def _get_redis():
    url = os.environ.get("REDIS_URL")
    if url:
        try:
            import redis
            client = redis.Redis.from_url(url)
            client.ping()
            return client, "redis"
        except Exception:
            pass
    import fakeredis
    return fakeredis.FakeStrictRedis(), "fakeredis"


def _load_anchor():
    """Return (entry, balances) from the signed snapshot, or (None, None).

    Fail-closed: the anchor's payload_hash must recompute correctly before
    its balances are trusted (same rule as scripts/balance_safety_check.py).
    """
    try:
        with open(LEDGER_FILE, "r", encoding="utf-8") as fh:
            chain = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None, None
    entry = next((e for e in chain
                  if e.get("ledger_id") == ANCHOR_ENTRY_ID), None)
    if entry is None:
        return None, None
    try:
        recomputed = lv.compute_payload_hash(entry["execution_context"])
    except Exception:
        return None, None
    if recomputed != entry.get("payload_hash"):
        return None, None
    return entry, balances_from_snapshot(entry["execution_context"])


def _dev_keys():
    try:
        with open(DEV_SECRET_FILE, "rb") as fh:
            secret = fh.read().strip()
        with open(DEV_PUBKEY_FILE, "r", encoding="utf-8") as fh:
            pubkey = fh.read().strip()
        return secret, pubkey
    except OSError:
        return None, None


class LedgerAPI:
    def __init__(self):
        self.redis, self.redis_backend = _get_redis()
        self.monitor = VelocityMonitor(self.redis)
        self.tx_cache = {}          # tx-id -> cached verdict (idempotency)
        self.audited_tenants = {"acme"}

    def post_transaction(self, tenant: str, body: dict):
        if tenant not in self.audited_tenants:
            return 404, {"error": "unknown_tenant", "tenant": tenant}

        extra = set(body) - VALID_TX_FIELDS
        if extra:
            return 400, {"error": "unexpected_fields", "fields": sorted(extra)}

        tx_id = body.get("id")
        account_id = body.get("accountId")
        amount = body.get("amount")
        description = body.get("description", "")
        unit = body.get("unit", "minor")

        if not isinstance(tx_id, str) or not tx_id:
            return 400, {"error": "missing_or_invalid_id"}
        if not isinstance(account_id, str) or not account_id:
            return 400, {"error": "missing_or_invalid_accountId"}
        if isinstance(amount, bool) or not isinstance(amount, int):
            # Integer-only at the API boundary: floats invite silent rounding;
            # fractional major units are handled by the exact-cent check below.
            return 400, {"error": "amount_must_be_numeric",
                         "detail": "amount must be an integer in the given "
                                   "unit (cents for minor, dollars for major)"}
        if unit not in ("major", "minor"):
            return 400, {"error": "unit_must_be_major_or_minor"}

        if tx_id in self.tx_cache:
            cached = dict(self.tx_cache[tx_id])
            status = cached.pop("_status")
            cached["duplicate"] = True
            return status, cached

        anchor, balances = _load_anchor()
        if anchor is None or balances is None:
            return 503, {"error": "anchor_snapshot_unverifiable"}
        if account_id not in balances:
            return 404, {"error": "account_not_in_anchored_snapshot",
                         "account": account_id}
        pre = balances[account_id]
        if pre["currency"] != "USD":
            return 503, {"error": "anchor_currency_unexpected",
                         "currency": pre["currency"]}

        # Unit convention. The anchored snapshot is stored in MINOR units
        # (cents): cash = 100000 means $1,000.00.
        # - unit "minor" (default): amount is integer cents -> used directly.
        # - unit "major": amount is dollars -> scaled to cents EXACTLY; a
        #   sub-cent remainder is rejected rather than silently rounded.
        delta_cents = amount * 100 if unit == "major" else amount
        if abs(delta_cents) > MAX_DELTA_CENTS:
            return 400, {"error": "amount_not_exact_in_cents",
                         "detail": f"{amount} ({unit} units) overflows the "
                                   "exact-integer cent range; refusing to "
                                   "round silently"}
        amount_units = amount
        post = pre["amount"] + delta_cents  # signed-delta convention, cents
        overdrawn = post < 0
        tx_digest = lv._digest(lv.canonical_json(body))

        # Risk score: cent-accurate magnitude. $1k per point for large moves;
        # any outgoing movement floors at the AUTHZ band (60) so debits can
        # never be admitted autonomously regardless of size.
        risk_score = max(abs(delta_cents) // 100000, 1)
        affects_authz = delta_cents < 0  # funds moving OUT of an account
        effective_score = apply_overrides(risk_score,
                                          affects_authz=affects_authz)
        policy = determine_policy(effective_score)
        velocity_cost = min(int(effective_score), 100)

        result = {
            "tx_id": tx_id,
            "tenant": tenant,
            "account": account_id,
            "tx_payload_hash": tx_digest,
            "amount_units": amount_units,
            "unit_convention": unit,
            "snapshot_unit_convention": "minor (cents)",
            "balance_before_cents": pre["amount"],
            "delta_cents": delta_cents,
            "balance_after_cents": post,
            "currency": pre["currency"],
            "risk_score": risk_score,
            "effective_risk_score": int(effective_score),
            "velocity_cost": velocity_cost,
            "approval_policy_required": getattr(policy, "value", str(policy)),
            "anchor_ledger_id": anchor.get("ledger_id"),
            "anchor_payload_hash": anchor.get("payload_hash"),
            "description": description,
        }
        if abs(delta_cents) >= 2 * abs(pre["amount"]) and pre["amount"] > 0:
            result["unit_convention_flag"] = (
                "|delta| >= 2x balance under the declared unit convention; "
                "double-check major/minor before resubmitting")

        if overdrawn:
            # Blocked transactions are NOT recorded in the velocity window
            # (they never execute) — same rule as VelocityMonitor.
            status, payload = 402, {**result, "verdict": "OVERDRAFT_BLOCKED",
                                    "velocity_admission": "NOT_ATTEMPTED",
                                    "error": "overdraft_blocked"}
        else:
            admitted = self.monitor.check_velocity(f"processor:{tenant}",
                                                   velocity_cost)
            result["velocity_admission"] = admitted
            if admitted == "VELOCITY_EXCEEDED":
                status, payload = 429, {**result,
                                        "verdict": "BALANCE_SAFE",
                                        "error": "velocity_exceeded"}
            else:
                # Balance-safe AND velocity-admitted, but still held PROPOSED:
                # approval gate must clear before execution.
                status, payload = 202, {
                    **result, "verdict": "BALANCE_SAFE",
                    "state": "PROPOSED_AWAITING_APPROVAL",
                    "note": "approval required before EXECUTING ledger entry",
                }
        self.tx_cache[tx_id] = {"_status": status, **payload}
        return status, payload

    def verify(self, tenant: str, body: dict):
        ledger_file = TENANT_LEDGER_FILES.get(tenant)
        if ledger_file is None:
            return 404, {"error": "unknown_tenant", "tenant": tenant}
        secret, pubkey = _dev_keys()
        if secret is None or pubkey is None:
            return 503, {"verified": False,
                         "error": "verification_keys_unavailable"}
        try:
            with open(ledger_file, "r", encoding="utf-8") as fh:
                entries = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            return 200, {"verified": False, "error": f"ledger_read_failed: {exc}"}
        errors = lv.verify_chain(entries, secret, pubkey)
        entry_id = body.get("auditId")
        expected = body.get("expectedHash")
        if entry_id is not None:
            match = next((e for e in entries
                          if e.get("ledger_id") == entry_id), None)
            if match is None:
                errors.append(f"auditId {entry_id!r} not found in ledger")
            elif expected is not None and match.get("current_hash") != expected:
                errors.append(
                    f"expectedHash mismatch for {entry_id}: "
                    f"{expected!r} != {match.get('current_hash')!r}")
        return 200, {"verified": not errors, "errors": errors,
                     "entries_checked": len(entries)}


_api = None


def get_api():
    global _api
    if _api is None:
        _api = LedgerAPI()
    return _api


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, payload: dict):
        data = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        if self.path == "/healthz":
            api = get_api()
            self._send(200, {"ok": True, "redis_backend": api.redis_backend})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self):  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw.decode("utf-8"))
                if not isinstance(body, dict):
                    raise ValueError("body must be a JSON object")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                self._send(400, {"error": "malformed_json_body"})
                return
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            route = parse_route(self.path)
            api = get_api()
            is_tx_endpoint = bool(route and route[1] == "transactions")
            if is_tx_endpoint:
                # Financial mutation endpoint: never guess the encoding.
                # curl's default Content-Type (form-urlencoded) is rejected
                # outright — send a JSON body with an explicit header.
                if ctype != "application/json":
                    self._send(415, {
                        "error": "unsupported_media_type",
                        "content_type": ctype or "(missing)",
                        "hint": ("add -H 'Content-Type: application/json' "
                                 "(curl defaults to form-urlencoded; this "
                                 "endpoint accepts strict JSON only)")})
                    return
            elif ctype not in ("application/json", ""):
                self._send(415, {"error": "unsupported_media_type",
                                 "content_type": ctype})
                return
            if route:
                tenant, resource = route
                if resource == "transactions":
                    status, payload = api.post_transaction(tenant, body)
                elif resource == "verify":
                    status, payload = api.verify(tenant, body)
                else:
                    status, payload = 404, {"error": "not_found",
                                            "route": self.path}
            else:
                status, payload = 404, {"error": "not_found",
                                        "route": self.path}
            self._send(status, payload)
        except Exception as exc:  # fail closed, never hang the socket
            self._send(500, {"error": "internal", "detail": str(exc)})

    def log_message(self, fmt, *args):
        sys.stderr.write("[ledger-api] %s\n" % (fmt % args))


def main():
    port = int(os.environ.get("PORT", "3000"))
    api = get_api()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"ledger-api listening on 127.0.0.1:{port} "
          f"(redis={api.redis_backend})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
