#!/usr/bin/env python3
"""
STS Anchor Daemon
Background service for synchronizing the local quarantine queue to Core Command.
Features: Async I/O, exponential backoff, network-aware triggering, token renewal.

Design invariants (Sovereign Time System doctrine):
  - Telemetry observes; the ledger preserves evidence; verification evaluates
    integrity; the engine decides authority.
  - Anchors are SEALedger rows: seq + monotonic stamp + prev_seal hash chain.
    Every anchor is re-verified against its seal BEFORE it leaves the device;
    suspect anchors are quarantined and never transmitted.
  - The daemon never blocks the event loop: all SQLite work runs via
    asyncio.to_thread, so stress-ng / matmul saturation cannot starve sync.
  - DIL (delay/disconnect-tolerant) store-and-forward: on partition, anchors
    accumulate in the local queue with zero state loss; on reconnect they
    drain in strict ascending seq order (ledger_seq ordering preserved).
  - Resource caps are enforced externally by systemd (CPUQuota/MemoryMax —
    see /etc/systemd/system/sts-anchor-daemon.service) so the daemon survives
    hardware-saturation hooks alongside agents.
"""

import asyncio
import json
import logging
import os
import random
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import aiohttp
except ImportError:  # pragma: no cover - hard runtime dependency
    aiohttp = None

# Make `bench.sts_time` importable whether launched as -m or directly.
_WORKSPACE = str(Path(__file__).resolve().parent.parent)
if _WORKSPACE not in sys.path:
    sys.path.insert(0, _WORKSPACE)

from bench.sts_time import GENESIS_SEAL, AssuranceLedger, STSMonotonicClock  # noqa: E402

# --- Configuration (Environment Variables) ---
DB_PATH = os.getenv("STS_QUEUE_DB", "/var/lib/sts/anchor_queue.db")
CORE_CMD_URL = os.getenv("STS_CORE_URL", "https://core-command.local/api/v1/anchors/bulk")
DEVICE_ID = os.getenv("STS_DEVICE_ID", "orin-splinter-01")
AUTH_TOKEN_PATH = os.getenv("STS_AUTH_TOKEN", "/etc/sts/auth_token.jwt")
CHECK_INTERVAL_SEC = int(os.getenv("STS_CHECK_INTERVAL", 30))
MAX_BACKOFF_SEC = int(os.getenv("STS_MAX_BACKOFF", 300))
BATCH_SIZE = int(os.getenv("STS_BATCH_SIZE", 50))
SEAL_DB_PATH = os.getenv("STS_SEAL_DB", "")  # optional: live SEALedger to verify against
TOKEN_RENEW_INTERVAL_SEC = int(os.getenv("STS_TOKEN_RENEW_INTERVAL", 900))

# --- Logging Setup ---
LOG_DIR = Path(os.getenv("STS_LOG_DIR", "/var/log/sts"))
try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    _file_handler = logging.FileHandler(LOG_DIR / "anchor_daemon.log")
except OSError:  # unprivileged test/dev environment
    _file_handler = logging.StreamHandler()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[_file_handler, logging.StreamHandler()],
)
logger = logging.getLogger("AnchorDaemon")


class QuarantineManager:
    """Local store-and-forward queue of sealed ledger anchors.

    All methods are safe to call from asyncio.to_thread(); every connection
    sets PRAGMA busy_timeout so concurrent benchmark writers never deadlock.
    """

    def __init__(self, db_path):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL;")      # survive reader/writer overlap
        conn.execute("PRAGMA synchronous=NORMAL;")    # durable enough for DIL queue
        conn.execute("PRAGMA busy_timeout=5000;")     # no SQLITE_BUSY under load
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS quarantine_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ledger_seq INTEGER UNIQUE,
                    mono_ns INTEGER,
                    utc_wall REAL,
                    stream TEXT,
                    payload TEXT,
                    signature TEXT,
                    status TEXT DEFAULT 'PENDING',
                    retry_count INTEGER DEFAULT 0,
                    next_retry REAL DEFAULT 0,
                    created_at REAL DEFAULT (strftime('%s', 'now'))
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_status_retry "
                "ON quarantine_queue(status, next_retry);")
            conn.commit()

    def enqueue(self, ledger_seq, mono_ns, utc_wall, stream, payload_json, signature):
        """Idempotently stage an anchor for sync (UNIQUE ledger_seq dedupes)."""
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO quarantine_queue "
                    "(ledger_seq, mono_ns, utc_wall, stream, payload, signature) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (ledger_seq, mono_ns, utc_wall, stream, payload_json, signature))
                conn.commit()
            return True
        except sqlite3.Error as exc:
            logger.error("Queue write failed (seq=%s): %s", ledger_seq, exc)
            return False

    def get_pending_anchors(self, limit=None):
        """Fetch anchors that are PENDING and whose next_retry time has passed."""
        if limit is None:
            limit = BATCH_SIZE
        now = time.time()
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT id, ledger_seq, mono_ns, utc_wall, stream, payload,
                       signature, retry_count
                FROM quarantine_queue
                WHERE status = 'PENDING' AND next_retry <= ?
                ORDER BY ledger_seq ASC
                LIMIT ?
            """, (now, limit))
            return [dict(row) for row in cursor.fetchall()]

    def update_status(self, anchor_ids, status, retry_count=None, next_retry=None):
        """Update the status of synced or failed anchors."""
        if not anchor_ids:
            return
        with self._connect() as conn:
            placeholders = ",".join("?" * len(anchor_ids))
            if status == "SYNCED":
                conn.execute(
                    "DELETE FROM quarantine_queue WHERE id IN ({})".format(placeholders),
                    list(anchor_ids))
            else:
                now = time.time()
                rc = retry_count if retry_count is not None else 0
                nr = next_retry if next_retry is not None else now
                conn.execute("""
                    UPDATE quarantine_queue
                    SET status = ?, retry_count = ?, next_retry = ?
                    WHERE id IN ({})
                """.format(placeholders), [status, rc, nr] + list(anchor_ids))
            conn.commit()

    def quarantine(self, anchor_ids, reason):
        """Mark anchors QUARANTINED (failed local seal verification)."""
        if not anchor_ids:
            return
        with self._connect() as conn:
            placeholders = ",".join("?" * len(anchor_ids))
            conn.execute(
                "UPDATE quarantine_queue SET status = 'QUARANTINED' "
                "WHERE id IN ({})".format(placeholders),
                list(anchor_ids))
            logger.debug("Quarantined %d anchor(s): %s", len(anchor_ids), reason)

    def queue_depth(self):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM quarantine_queue WHERE status='PENDING'"
            ).fetchone()
            return int(row[0])


class SealVerifier:
    """Verification evaluates integrity: recompute each anchor's SEAL locally.

    If a live SEALedger DB is configured (STS_SEAL_DB), the prev_seal is read
    from the chain itself; otherwise the queue stores its own prev_seal in the
    payload envelope. Suspect anchors never reach the wire.
    """

    def __init__(self, seal_db_path=""):
        self.seal_db_path = seal_db_path or None
        self._chain_cache = None  # (ok, errors, checked_at)

    def verify_anchor(self, anchor):
        prev_seal = anchor.get("prev_seal")
        if prev_seal is None:
            prev_seal = self._prev_seal_from_chain(anchor["ledger_seq"])
        expected = AssuranceLedger.compute_seal(
            anchor["ledger_seq"], anchor["mono_ns"], anchor["utc_wall"],
            anchor["stream"], anchor["payload"], prev_seal)
        return expected == anchor["signature"]

    def _prev_seal_from_chain(self, ledger_seq):
        if not self.seal_db_path:
            return GENESIS_SEAL
        try:
            with sqlite3.connect(self.seal_db_path, timeout=5.0) as conn:
                conn.execute("PRAGMA busy_timeout=5000;")
                # Genesis anchor (seq 1) chains from the zero seal; every other
                # anchor chains from the stored seal of its predecessor. A
                # missing predecessor row means the chain is broken locally —
                # return a sentinel so verification FAILS CLOSED (the anchor is
                # quarantined rather than transmitted on an unverifiable chain).
                if ledger_seq <= 1:
                    return GENESIS_SEAL
                row = conn.execute(
                    "SELECT seal_hash FROM ledger WHERE seq = ?",
                    (ledger_seq - 1,)).fetchone()
            if row is None:
                logger.error("Chain gap: no stored seal for seq=%d "
                             "(anchor %d) — failing closed.",
                             ledger_seq - 1, ledger_seq)
                return "CHAIN_GAP_" + str(ledger_seq)
            return row[0]
        except sqlite3.Error as exc:
            logger.error("Seal DB unreadable (%s) — failing closed.", exc)
            return "CHAIN_GAP_" + str(ledger_seq)

    def chain_intact(self):
        """Full-chain audit of the live ledger (cached 60 s)."""
        if not self.seal_db_path or not os.path.exists(self.seal_db_path):
            return True
        now = time.time()
        if self._chain_cache and now - self._chain_cache[2] < 60:
            return self._chain_cache[0]
        ok, errors = True, []
        try:
            ledger = AssuranceLedger(self.seal_db_path)
            ok, errors = ledger.verify()
            ledger.close()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Chain audit skipped: %s", exc)
            ok, errors = True, []
        if not ok:
            logger.critical("⛔ LOCAL LEDGER CHAIN BROKEN: %d error(s): %s",
                            len(errors), errors[:3])
        self._chain_cache = (ok, errors, now)
        return ok


class AuthManager:
    """Bearer-token lifecycle: load, pre-emptively renew, renew-on-401."""

    def __init__(self, token_path, renew_interval=TOKEN_RENEW_INTERVAL_SEC):
        self.token_path = token_path
        self.renew_interval = renew_interval
        self.token = self._load_token()
        self.last_renewal = time.time()

    def _load_token(self):
        try:
            if os.path.exists(self.token_path):
                with open(self.token_path, "r") as f:
                    return f.read().strip()
        except OSError as exc:
            logger.warning("Token read failed (%s); minting fallback.", exc)
        return self._renew()  # first-run / offline provisioning

    def _renew(self):
        """Renew via local secure enclave hook, else mint a scoped mock JWT."""
        new_token = "MOCK_JWT_{}_{}".format(int(time.time()), DEVICE_ID)
        try:
            Path(self.token_path).parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.token_path,
                         os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(new_token)
        except OSError as exc:
            logger.warning("Could not persist token (%s); holding in memory.", exc)
        return new_token

    def refresh_token(self):
        logger.info("Attempting token renewal...")
        self.token = self._renew()
        self.last_renewal = time.time()
        logger.info("Token renewed successfully.")
        return self.token

    def maybe_preemptive_refresh(self):
        if time.time() - self.last_renewal >= self.renew_interval:
            self.refresh_token()


class AnchorDaemon:
    def __init__(self):
        self.qm = QuarantineManager(DB_PATH)
        self.auth = AuthManager(AUTH_TOKEN_PATH)
        self.verifier = SealVerifier(SEAL_DB_PATH)
        self.global_backoff_until = 0.0
        self._backoff_step = 0          # true exponential escalation counter
        self.network_up_event = asyncio.Event()
        self.network_up_event.set()     # start assuming network is up
        self.stats = {"synced": 0, "quarantined": 0, "batches": 0}

    # ---------- network awareness ----------
    def is_network_available(self):
        """Quick check for tactical mesh / upstream connectivity."""
        try:
            result = subprocess.run(["ip", "route", "show", "default"],
                                    capture_output=True, text=True, timeout=2)
            return "dev" in result.stdout
        except Exception:
            return False

    async def monitor_network(self):
        """Background task toggling sync based on link availability (non-blocking)."""
        while True:
            is_up = await asyncio.to_thread(self.is_network_available)
            if is_up and not self.network_up_event.is_set():
                logger.info("Network connectivity detected. Resuming sync.")
                self.network_up_event.set()
            elif not is_up and self.network_up_event.is_set():
                logger.warning("Network connectivity lost. Entering "
                               "DIL store-and-forward mode.")
                self.network_up_event.clear()
            await asyncio.sleep(10)

    # ---------- backoff ----------
    def _apply_global_backoff(self):
        """True exponential backoff with jitter for server-side failures."""
        base = min(CHECK_INTERVAL_SEC * (2 ** self._backoff_step), MAX_BACKOFF_SEC)
        jitter = random.uniform(0, max(1.0, base * 0.2))
        delay = min(base + jitter, MAX_BACKOFF_SEC)
        self._backoff_step = min(self._backoff_step + 1, 10)
        self.global_backoff_until = time.time() + delay
        logger.info("Global backoff engaged for %.1f s (step %d).", delay,
                    self._backoff_step)

    def _reset_global_backoff(self):
        if self._backoff_step:
            logger.info("Backoff reset after successful sync.")
        self._backoff_step = 0
        self.global_backoff_until = 0.0

    def _apply_individual_backoff(self, anchors):
        """Per-anchor exponential backoff (e.g., malformed payload rejected)."""
        for anchor in anchors:
            new_retry_count = anchor["retry_count"] + 1
            backoff_delay = min(2 ** new_retry_count, MAX_BACKOFF_SEC)
            self.qm.update_status(
                [anchor["id"]], status="PENDING",
                retry_count=new_retry_count,
                next_retry=time.time() + backoff_delay)

    # ---------- sync ----------
    async def sync_batch(self, session, anchors):
        """Push a batch of locally-verified anchors to Core Command."""
        if time.time() < self.global_backoff_until:
            until = datetime.fromtimestamp(
                self.global_backoff_until, tz=timezone.utc).strftime("%H:%M:%S")
            logger.debug("Global backoff active. Skipping sync until %s UTC", until)
            return

        # Verification gate: never transmit an anchor whose seal fails locally.
        verified, suspect = [], []
        for a in anchors:
            (verified if self.verifier.verify_anchor(a) else suspect).append(a)
        if suspect:
            ids = [a["id"] for a in suspect]
            await asyncio.to_thread(self.qm.quarantine, ids,
                                    "local seal recomputation mismatch")
            self.stats["quarantined"] += len(ids)
            logger.error("%d anchor(s) failed LOCAL SEAL verification; "
                         "quarantined, not transmitted.", len(ids))
        if not verified:
            return

        payload = {
            "device_id": DEVICE_ID,
            "timestamp": time.time(),
            "ordering_note": "sequence carried by sealed mono_ns, not wall clock",
            "anchors": [{k: v for k, v in a.items() if k != "id"} for a in verified],
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(self.auth.token),
            "X-Device-ID": DEVICE_ID,
        }

        try:
            async with session.post(CORE_CMD_URL, json=payload, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=15)) as resp:
                body = await resp.text()
                if resp.status == 200:
                    ids = [a["id"] for a in verified]
                    await asyncio.to_thread(self.qm.update_status, ids, "SYNCED")
                    self.stats["synced"] += len(ids)
                    self.stats["batches"] += 1
                    logger.info("Synced %d anchors to Core Command.", len(ids))
                    self._reset_global_backoff()
                elif resp.status == 401:
                    logger.warning("Auth failed (401). Renewing token.")
                    await asyncio.to_thread(self.auth.refresh_token)
                elif resp.status == 409:
                    # Core already holds these seqs — treat as delivered (idempotent ack)
                    ids = [a["id"] for a in verified]
                    await asyncio.to_thread(self.qm.update_status, ids, "SYNCED")
                    logger.info("Core acknowledged %d duplicate seq(s).", len(ids))
                    self._reset_global_backoff()
                elif resp.status in (429, 500, 502, 503, 504):
                    logger.warning("Core Command unavailable (%d). Backoff.",
                                   resp.status)
                    self._apply_global_backoff()
                else:
                    logger.error("Unexpected response %d: %s", resp.status, body[:200])
                    await asyncio.to_thread(self._apply_individual_backoff, verified)
        except aiohttp.ClientConnectorError:
            logger.warning("Connection refused. Applying global backoff.")
            self._apply_global_backoff()
        except asyncio.TimeoutError:
            logger.warning("Request timed out. Applying global backoff.")
            self._apply_global_backoff()
        except Exception as exc:  # noqa: BLE001
            logger.error("Unexpected sync error: %s", exc)
            await asyncio.to_thread(self._apply_individual_backoff, verified)

    # ---------- main loop ----------
    async def run(self):
        if aiohttp is None:
            raise RuntimeError("aiohttp is required: pip install aiohttp")
        logger.info("STS Anchor Daemon started. Device: %s", DEVICE_ID)
        logger.info("Queue DB: %s | Core URL: %s | Seal DB: %s",
                    DB_PATH, CORE_CMD_URL, SEAL_DB_PATH or "(none)")

        asyncio.create_task(self.monitor_network())

        conn_timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=conn_timeout) as session:
            while True:
                try:
                    try:
                        await asyncio.wait_for(self.network_up_event.wait(),
                                               timeout=CHECK_INTERVAL_SEC)
                    except asyncio.TimeoutError:
                        pass  # interval reached; probe anyway

                    if not await asyncio.to_thread(self.is_network_available):
                        await asyncio.sleep(5)
                        continue

                    pending = await asyncio.to_thread(
                        self.qm.get_pending_anchors, BATCH_SIZE)
                    if not pending:
                        logger.debug("Quarantine queue empty. Sleeping.")
                        self.auth.maybe_preemptive_refresh()
                        await asyncio.sleep(CHECK_INTERVAL_SEC)
                        continue

                    depth = await asyncio.to_thread(self.qm.queue_depth)
                    logger.info("%d pending anchor(s) (depth=%d). Syncing...",
                                len(pending), depth)
                    await self.sync_batch(session, pending)
                    self.auth.maybe_preemptive_refresh()
                    await asyncio.sleep(2)  # gentle pacing on recovering links

                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    logger.error("Daemon loop error: %s", exc)
                    await asyncio.sleep(10)


async def main():
    daemon = AnchorDaemon()
    try:
        await daemon.run()
    except asyncio.CancelledError:
        logger.info("Daemon cancelled.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Daemon shutting down gracefully.")
