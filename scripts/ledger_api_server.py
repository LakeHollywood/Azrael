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

import base64
import json
import sys
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ledger_verifier as lv  # noqa: E402
from approval_gate.risk import (  # noqa: E402
    apply_overrides,
    create_approval_record,
    determine_policy,
)
from audit_log import get_logger  # noqa: E402
from task_runner import (  # noqa: E402
    Agent,
    AgentState,
    ApprovalRequired,
    Task,
    TaskCapability,
    TaskContext,
    TaskMode,
    TaskPolicy,
    TaskStatus,
)
from velocity_monitor import VelocityMonitor  # noqa: E402
from scripts.balance_safety_check import balances_from_snapshot  # noqa: E402


def _audit(event_type: str, *, tenant=None, outcome="info", actor="system",
           resource=None, details=None):
    """Best-effort structured audit record (never breaks the request path)."""
    try:
        get_logger().log_event(event_type, actor=actor, outcome=outcome,
                               tenant=tenant, resource=resource,
                               details=details)
    except Exception as exc:  # pragma: no cover - defensive
        sys.stderr.write(f"[ledger-api] audit write failed: {exc}\n")


# Result fields mirrored into audit records (compact; never log full bodies).
_AUDIT_TX_FIELDS = ("tx_id", "account", "tx_payload_hash", "delta_cents",
                    "balance_before_cents", "balance_after_cents",
                    "effective_risk_score", "approval_policy_required",
                    "velocity_admission", "description")


def _audit_tx_fields(result: dict) -> dict:
    return {k: result[k] for k in _AUDIT_TX_FIELDS if k in result}

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
# Verification keys are out-of-band trust material and must never be
# committed (see scripts/secret_scan.py deny list).  Preferred source is the
# environment; the .ledgerdev/ directory is the local dev fallback.
ENV_HMAC_SECRET_B64 = "LEDGER_HMAC_SECRET_B64"
ENV_PUBKEY_B64 = "LEDGER_ED25519_PUBKEY_B64"
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


def _env_keys():
    """Return (hmac_secret_bytes, ed25519_pubkey_b64) from the environment.

    Used by production/CI, where the ledger-audit workflow injects
    LEDGER_HMAC_SECRET_B64 / LEDGER_ED25519_PUBKEY_B64 as secrets/vars.
    Returns None when neither variable is set (so callers fall back to dev
    key material) and (None, None) when they are present but malformed —
    fail closed either way.
def _dev_keys():
    """Return (hmac_secret_bytes, ed25519_pubkey_b64) or (None, None).

    This reads the two files scripts/generate_dev_ledger_keys.py creates:
    .ledgerdev/secret (raw HMAC-SHA256 secret bytes) and .ledgerdev/pub.b64
    (base64url Ed25519 public key).

    Resolution order: environment variables first (production/CI), then the
    gitignored .ledgerdev/ files (local development).  Fail closed: callers
    must refuse verification when either half is missing.
    """
    secret_b64 = os.environ.get(ENV_HMAC_SECRET_B64)
    pubkey = os.environ.get(ENV_PUBKEY_B64)
    if not secret_b64 and not pubkey:
        return None
    try:
        return base64.b64decode(secret_b64), (pubkey or "").strip()
    except Exception:
        return None, None


def _dev_keys():
    """Return (hmac_secret_bytes, ed25519_pubkey_b64) or (None, None).

    Reads the gitignored .ledgerdev/ files generated by
    scripts/generate_dev_ledger_keys.py.  Fail closed: callers must refuse
    verification when either half is missing.
    """
    module = sys.modules[__name__]
    try:
        with open(module.DEV_SECRET_FILE, "rb") as fh:
            secret = fh.read().strip()
        with open(module.DEV_PUBKEY_FILE, "r", encoding="utf-8") as fh:
            pubkey = fh.read().strip()
        return secret, pubkey
    except OSError:
        return None, None


def _verification_keys():
    """Return (hmac_secret_bytes, ed25519_pubkey_b64) or (None, None).

    Resolution order: environment variables first (production/CI), then the
    gitignored .ledgerdev/ files (local development).  Fail closed: callers
    must refuse verification when either half is missing.
    """
    env = _env_keys()
    if env is not None:
        return env
    return _dev_keys()


class LedgerAPI:
    """The ledger control-plane AGENT.

    Agent/task separation (see task_runner.py): this class owns identity,
    lifecycle, shared state (Redis backend, velocity monitor, idempotency
      # cache) and supervision/audit — i.e. *who* runs and *whether* it may run.
    The actual request-time work lives in discrete TASKS:

      ``admit-transaction``  one transaction admission (balance/risk/velocity)
      ``verify-chain``       one whole-ledger verification pass

    Handlers below are thin adapters: they parse/validate the HTTP-facing
    contract (status codes unchanged), then execute the corresponding Task
    through the agent, which enforces fail-closed policy (unknown tenant,
    unregistered task, stopped agent => refused before execution) and writes
    the correlated audit records.
    """

    #: per-request wall-clock bound for admission tasks; a hung Redis or
    #: snapshot read must surface as TIMED_OUT, never wedge the handler.
    TX_TIMEOUT_SECONDS = 5.0
    VERIFY_TIMEOUT_SECONDS = 15.0

    def __init__(self):
        self.redis, self.redis_backend = _get_redis()
        self.monitor = VelocityMonitor(self.redis)
        self.tx_cache = {}          # tx-id -> cached verdict (idempotency)
        self._read_only_dispatch = False  # strict-isolation kill switch
        self.audited_tenants = {"acme"}
        self.agent = Agent(
            "ledger-api",
            name="Ledger Control-Plane Agent",
            roles=("ledger", "hitl-gate"),
            metadata={"redis_backend": self.redis_backend},
            # PRIVILEGED execution context: this agent's default grant is the
            # ceiling for everything it dispatches. Read-only callers get a
            # narrowed TaskContext (see post_transaction/verify).
            context=TaskContext.privileged(
                gated=(TaskCapability.FINANCIAL_MUTATION,),
                extra=(TaskCapability.READ, TaskCapability.AUDIT_WRITE,
                       TaskCapability.LEDGER_VERIFY),
            ),
        )
        self.agent.register(
            Task("admit-transaction", self._task_admit_transaction,
                 gate=self._gate_known_tenant,
                 policy=TaskPolicy(timeout_seconds=self.TX_TIMEOUT_SECONDS),
                 description="Admit/reject one transaction at request time",
                 # GATED financial action: only contexts holding
                 # FINANCIAL_MUTATION can execute it (enforced fail-closed
                 # by the agent before the gate/body ever run).
                 # Read-only observation of balances/risk (no side effects)
                 # plus the gated mutation itself; enforced fail-closed by
                 # the agent before gate/body run.
                 requires=(TaskCapability.READ,
                           TaskCapability.FINANCIAL_MUTATION)),
            Task("verify-chain", self._task_verify_chain,
                 gate=self._gate_verifiable_tenant,
                 policy=TaskPolicy(timeout_seconds=self.VERIFY_TIMEOUT_SECONDS),
                 description="Recompute payload hashes and walk one ledger chain",
                 # Read-only observation of the chain: safe for READ_ONLY
                 # agents/contexts.
                 # Pure chain recomputation: readable by READ_ONLY contexts.
                 requires=(TaskCapability.READ,)),
        )
        self.agent.start()

    # -- fail-closed gates ---------------------------------------------------

    @staticmethod
    def _gate_known_tenant(t: Task, kwargs: dict) -> None:
        """Refuse unknown tenants before any task code runs (fail closed)."""
        api, tenant = kwargs["api"], kwargs["tenant"]
        if tenant not in api.audited_tenants:
            raise ApprovalRequired(f"unknown_tenant:{tenant}")

    @staticmethod
    def _gate_verifiable_tenant(t: Task, kwargs: dict) -> None:
        api, tenant = kwargs["api"], kwargs["tenant"]
        if tenant not in TENANT_LEDGER_FILES:
            raise ApprovalRequired(f"unknown_tenant:{tenant}")

    # -- task bodies ----------------------------------------------------------

    def _task_admit_transaction(self, ctx: TaskContext, *, api: "LedgerAPI",
                                tenant: str, body: dict) -> tuple:
        # Defense in depth: the structural check lives in the agent
        # (context.requires FINANCIAL_MUTATION was enforced before this line
        # ran); re-check here so even a direct call cannot bypass isolation.
        if not ctx.can(TaskCapability.FINANCIAL_MUTATION):
            raise ApprovalRequired(
                f"context_mode:{ctx.mode.value} cannot invoke gated "
                "financial action")
        return api._admit_transaction(tenant, body)

    def _task_verify_chain(self, ctx: TaskContext, *, api: "LedgerAPI",
                           tenant: str, body: dict) -> tuple:
        return api._verify_impl(tenant, body)

    def _dispatch_context(self, tenant: str, gated: bool) -> TaskContext:
        """Build the per-request execution context (strict boundary).

        * tenant scoping: the context carries exactly one tenant; a task may
          never act across tenants (checked against the agent's grant).
        * non-financial endpoints (verify) are dispatched through a
          READ_ONLY view — structurally incapable of money movement even if
          a bug routed them at admit-transaction.
        * financial endpoints require an explicit caller grant
          (``self.financial_grant``, set by the operator/HITL layer); with
          no grant the request runs under a read-only context and the agent
          refuses it BEFORE any gated code executes.
        """
        base = self.agent.default_context
        scoped = base.narrowed(tenant=tenant)
        if not gated:
            # Read-only view of the PRIVILEGED grant: keeps READ (so verify-
            # chain executes) but strips every gated capability, so this
            # context is structurally incapable of money movement.
            return TaskContext.derive((TaskCapability.READ,), tenant=tenant)
        ro_view = TaskContext.derive((TaskCapability.READ,), tenant=tenant)
        if getattr(self, "_read_only_dispatch", False):
            return ro_view
        env_default = os.environ.get("LEDGER_FINANCIAL_MODE", "granted")
        if env_default == "read_only":
            return ro_view
        grant = getattr(self, "financial_grant", None)
        if grant is None:
            # Default posture: PRIVILEGED (the admission pipeline runs; the
            # approval gate still holds every admitted transaction as
            # PROPOSED_AWAITING_APPROVAL — nothing executes without HITL).
            # Fail-closed read-only dispatch is available per-process via
            # LEDGER_FINANCIAL_MODE=read_only or per-instance via
            # api.agent.dispatch_context = TaskContext.read_only(...).
            return scoped
        return scoped.narrowed(actor=grant.get("actor"),
                               metadata=dict(grant))

    # -- task execution helper --------------------------------------------------

    def _execute(self, task_name: str, context=None, **kwargs) -> tuple:
        """Run a registered task via the agent; map TaskResult to HTTP pair.

        Returns (status, payload). Policy/crash outcomes that would escape
        the old direct-call path are mapped onto the same status codes the
        API has always returned, so client behaviour is unchanged while the
        execution now flows through the audited task boundary.
        """
        res = self.agent.run_task(task_name, context=context, api=self, **kwargs)
        if res.ok:
            status, payload = res.output
            return status, payload
        if res.status is TaskStatus.REJECTED:
            # Gate refusal: keep the historical response shape.
            if "unknown_tenant" in (res.error or ""):
                tenant = kwargs.get("tenant")
                _audit("tx.rejected" if task_name == "admit-transaction"
                       else "verify.rejected",
                       tenant=tenant, outcome="rejected",
                       resource=task_name.split("-")[0],
                       details={"error": "unknown_tenant"})
                key = ("unknown_tenant" if task_name == "admit-transaction"
                       else "unknown_tenant")
                payload = {"error": key, "tenant": kwargs.get("tenant")}
                return (404, payload)
            if res.error_type == "InsufficientCapabilities":
                # Execution-context isolation refused the action BEFORE any
                # gated code ran (e.g. a read-only context invoking the
                # gated financial task). Distinct, machine-readable error.
                _audit("tx.rejected" if task_name == "admit-transaction"
                       else "verify.rejected",
                       tenant=kwargs.get("tenant"), outcome="rejected",
                       resource=task_name.split("-")[0],
                       details={"error": "insufficient_capabilities",
                                "context_mode": res.context_mode,
                                "required_capabilities":
                                    res.as_dict()["required_capabilities"]})
                return 403, {"error": "insufficient_capabilities",
                             "detail": res.error,
                             "context_mode": res.context_mode,
                             "task": res.as_dict()}
            return 403, {"error": "task_rejected",
                         "detail": res.error, "task": res.as_dict()}
        if res.status is TaskStatus.TIMED_OUT:
            return 503, {"error": "task_timeout",
                         "detail": res.error, "task": res.as_dict()}
        if res.status is TaskStatus.SKIPPED:
            return 503, {"error": "agent_not_running",
                         "detail": res.error, "task": res.as_dict()}
        # FAILED: task body raised — same fail-closed posture as a 500.
        return 500, {"error": "internal", "detail": res.error,
                     "task": res.as_dict()}

    def set_financial_grant_actor(self, actor: str) -> None:
        """Tag financial dispatches with the approving actor (audit detail)."""
        self.financial_grant = {"actor": actor}

    def dispatch_as_read_only(self) -> None:
        """Flip this instance to strict isolation: every transaction request
        is dispatched under a READ_ONLY context and structurally refused by
        the agent (403 insufficient_capabilities) BEFORE any gated code
        runs. Verification keeps working (it requires no capabilities)."""
        self._read_only_dispatch = True

    def restore_privileged_dispatch(self) -> None:
        self._read_only_dispatch = False

    def health(self) -> dict:
        """Agent health surfaced on /healthz (separate from task results)."""
        h = self.agent.health()
        h["redis_backend"] = self.redis_backend
        return h

    # -- endpoints (thin adapters over tasks) ------------------------------------

    def post_transaction(self, tenant: str, body: dict):
        return self._execute("admit-transaction",
                             context=self._dispatch_context(tenant, gated=True),
                             tenant=tenant, body=body)

    def verify(self, tenant: str, body: dict):
        # Read-only action: dispatched through a READ_ONLY context, which by
        # construction can never reach a gated financial task.
        return self._execute("verify-chain",
                             context=self._dispatch_context(tenant, gated=False),
                             tenant=tenant, body=body)

    # -- original implementations, now task bodies -------------------------------

    def _admit_transaction(self, tenant: str, body: dict):
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
            _audit("tx.duplicate", tenant=tenant, outcome="cached",
                   resource="transactions",
                   details={"tx_id": tx_id, "cached_status": status})
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
            _audit("tx.overdraft_blocked", tenant=tenant, outcome="blocked",
                   resource="transactions", actor=description or "system",
                   details=_audit_tx_fields(result))
        else:
            admitted = self.monitor.check_velocity(f"processor:{tenant}",
                                                   velocity_cost)
            result["velocity_admission"] = admitted
            if admitted == "VELOCITY_EXCEEDED":
                status, payload = 429, {**result,
                                        "verdict": "BALANCE_SAFE",
                                        "error": "velocity_exceeded"}
                _audit("tx.velocity_throttled", tenant=tenant,
                       outcome="throttled", resource="transactions",
                       details=_audit_tx_fields(result))
            else:
                # Balance-safe AND velocity-admitted, but still held PROPOSED:
                # approval gate must clear before execution.
                status, payload = 202, {
                    **result, "verdict": "BALANCE_SAFE",
                    "state": "PROPOSED_AWAITING_APPROVAL",
                    "note": "approval required before EXECUTING ledger entry",
                }
                approval_record = create_approval_record(
                    effective_score, operation=f"tx:{tx_id}",
                    actor=description or "system",
                    extra={"tenant": tenant, "account": account_id,
                           "tx_payload_hash": tx_digest})
                _audit("tx.proposed", tenant=tenant, outcome="proposed",
                       resource="transactions",
                       details={**_audit_tx_fields(result),
                               "approval_record_id":
                                   approval_record["record_id"],
                               "approval_policy":
                                   approval_record["approval_policy"]})
        self.tx_cache[tx_id] = {"_status": status, **payload}
        return status, payload

    def _verify_impl(self, tenant: str, body: dict):
        ledger_file = TENANT_LEDGER_FILES.get(tenant)
        if ledger_file is None:
            # Defensive: the gate already refuses unknown tenants (fail
            # closed before execution); this keeps the direct-call path safe.
            _audit("verify.rejected", tenant=tenant, outcome="rejected",
                   resource="verify", details={"error": "unknown_tenant"})
            return 404, {"error": "unknown_tenant", "tenant": tenant}
        secret, pubkey = _dev_keys()
        if secret is None or pubkey is None:
            _audit("verify.unavailable", tenant=tenant, outcome="unavailable",
                   resource="verify",
                   details={"error": "verification_keys_unavailable"})
            return 503, {"verified": False,
                         "errors": ["verification_keys_unavailable: dev key "
                                    "material missing (.ledgerdev/secret and "
                                    ".ledgerdev/pub.b64); generate with "
                                    "scripts/generate_dev_ledger_keys.py"],
                         "entries_checked": 0}
        try:
            with open(ledger_file, "r", encoding="utf-8") as fh:
                entries = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            _audit("verify.ledger_read_failed", tenant=tenant,
                   outcome="error", resource="verify", details={"error": str(exc)})
            return 200, {"verified": False,
                         "errors": [f"ledger_read_failed: {exc}"],
                         "entries_checked": 0}
        errors = lv.verify_chain(entries, secret, pubkey)
        entry_id = body.get("auditId")
        expected = body.get("expectedHash")
        if entry_id is not None:
            match = next((e for e in entries
                          if e.get("ledger_id") == entry_id), None)
            if match is None:
                errors.append(f"Audit ID '{entry_id}' not found")
            elif expected is not None and match.get("current_hash") != expected:
                errors.append(
                    f"expectedHash mismatch for {entry_id}: "
                    f"{expected!r} != {match.get('current_hash')!r}")
        verified = not errors
        _audit("verify.chain_passed" if verified else "verify.chain_failed",
               tenant=tenant, outcome="verified" if verified else "failed",
               resource="verify",
               details={"entries_checked": len(entries),
                        "audit_id": entry_id, "errors": errors})
        return 200, {"verified": verified, "errors": errors,
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
    _audit("server.starting", resource="lifecycle", outcome="starting",
           details={"port": port, "redis_backend": api.redis_backend,
                    "audit_log_file": get_logger().path})
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"ledger-api listening on 127.0.0.1:{port} "
          f"(redis={api.redis_backend})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _audit("server.stopped", resource="lifecycle", outcome="stopped",
               details={"port": port})
        raise


if __name__ == "__main__":
    main()
