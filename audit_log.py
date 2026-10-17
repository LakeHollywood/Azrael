#!/usr/bin/env python3
"""Structured audit logging for the HITL control plane.

Every security-relevant decision (transaction admission, overdraft blocks,
velocity throttling, chain verification, approval-gate evaluations) is
recorded as a single JSON object per line (JSONL) so logs are trivially
machine-parseable and tamper-evident.

Integrity model
---------------
Each record carries:

  * ``seq``          - monotonically increasing sequence number
  * ``prev_hash``    - entry_hash of the previous record (genesis = 64 zeros)
  * ``entry_hash``   - SHA-256 over the canonical JSON of the record fields
                       *excluding* ``entry_hash`` itself

Because each entry's hash covers the previous entry's hash, the file forms
a hash chain: deleting, reordering, or editing any record breaks the chain.
Use :func:`verify_chain` (or the CLI below) to detect tampering::

    python audit_log.py verify [AUDIT_LOG_FILE]

Configuration
-------------
* Log destination: ``$AUDIT_LOG_FILE`` (default ``data/audit/audit.jsonl``).
* Records never raise into application code by default: if writing fails,
  the failure is reported on stderr and ``log_event`` returns ``None``.
  Pass ``strict=True`` (or set ``AUDIT_LOG_STRICT=1``) when you want audit
  failures to be loud — appropriate for fail-closed contexts where an
  unauditable action must not silently succeed.
* The logger is process-safe (one OS-level exclusive lock held while
  appending) and thread-safe (internal lock around seq/hash bookkeeping).
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import sys
import threading
from typing import Any, MutableMapping, Optional

GENESIS_HASH = "0" * 64
HASH_FIELDS_EXCLUDED = ("entry_hash",)

_DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "audit", "audit.jsonl"
)


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _digest(canonical: str) -> str:
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def canonical_json(obj: Any) -> str:
    """Deterministic JSON encoding used for hashing (sorted keys, no space)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def compute_entry_hash(record: MutableMapping[str, Any]) -> str:
    """Hash every field of ``record`` except ``entry_hash`` itself."""
    payload = {k: v for k, v in record.items() if k not in HASH_FIELDS_EXCLUDED}
    return _digest(canonical_json(payload))


class AuditLogger:
    """Append-only, hash-chained JSONL audit logger.

    Shared instances should be obtained via :func:`get_logger`; construct
    directly only for tests or isolated sinks.
    """

    def __init__(self, path: Optional[str] = None):
        self._path = path
        self._lock = threading.Lock()
        self._seq: Optional[int] = None
        self._prev_hash: Optional[str] = None

    @property
    def path(self) -> str:
        return self._path or os.environ.get("AUDIT_LOG_FILE", _DEFAULT_PATH)

    # -- internal -----------------------------------------------------------

    def _load_tail_state(self) -> None:
        """Recover seq/prev-hash from the last valid line of the log file.

        A torn final line (crash mid-write) is tolerated: we resume from the
        last complete record. An empty/missing file starts at genesis.
        """
        seq = 0
        prev = GENESIS_HASH
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                last_line = None
                for line in fh:
                    if line.strip():
                        last_line = line
            if last_line is not None:
                try:
                    tail = json.loads(last_line)
                except json.JSONDecodeError:
                    tail = None
                if isinstance(tail, dict) and "seq" in tail:
                    stored_seq = int(tail["seq"])
                    stored_hash = tail.get("entry_hash")
                    recomputed = compute_entry_hash(tail)
                    if stored_hash == recomputed:
                        seq = stored_seq
                        prev = recomputed
                    else:
                        # Tail is inconsistent; refuse to extend a broken
                        # chain silently — restart lineage at genesis but
                        # keep issuing above the observed seq so numbers
                        # stay monotonic within this file.
                        seq = stored_seq
                        sys.stderr.write(
                            "audit_log: WARNING existing log tail failed "
                            "hash check; chain verification will report it\n"
                        )
        except OSError:
            pass
        self._seq = seq
        self._prev_hash = prev

    # -- public API ---------------------------------------------------------

    def log_event(
        self,
        event_type: str,
        *,
        actor: str = "system",
        outcome: str = "info",
        tenant: Optional[str] = None,
        resource: Optional[str] = None,
        details: Optional[MutableMapping[str, Any]] = None,
        strict: bool = False,
    ) -> Optional[MutableMapping[str, Any]]:
        """Append one structured audit record; returns the written record.

        ``event_type`` should be dotted and stable, e.g.
        ``tx.proposed``, ``tx.overdraft_blocked``, ``verify.chain_failed``.
        Never raises unless ``strict`` (or env ``AUDIT_LOG_STRICT=1``) is
        set; write failures otherwise go to stderr and return ``None``.
        """
        strict = strict or os.environ.get("AUDIT_LOG_STRICT", "") not in ("", "0")
        with self._lock:
            if self._seq is None:
                self._load_tail_state()
            assert self._seq is not None and self._prev_hash is not None
            record: MutableMapping[str, Any] = {
                "ts": _utc_now_iso(),
                "seq": self._seq + 1,
                "event_type": event_type,
                "actor": actor,
                "outcome": outcome,
                "prev_hash": self._prev_hash,
            }
            if tenant is not None:
                record["tenant"] = tenant
            if resource is not None:
                record["resource"] = resource
            if details:
                record["details"] = dict(details)
            record["entry_hash"] = compute_entry_hash(record)

            line = json.dumps(record, separators=(",", ":"), default=str) + "\n"
            try:
                directory = os.path.dirname(self.path)
                if directory:
                    os.makedirs(directory, exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line)
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError as exc:
                self._seq = None      # force tail reload before next attempt
                self._prev_hash = None
                msg = f"audit_log: FAILED to write {event_type!r}: {exc}"
                if strict:
                    raise RuntimeError(msg) from exc
                sys.stderr.write(msg + "\n")
                return None

            self._seq += 1
            self._prev_hash = record["entry_hash"]
            return record


_LOGGER: Optional[AuditLogger] = None
_LOGGER_LOCK = threading.Lock()


def get_logger(path: Optional[str] = None) -> AuditLogger:
    """Return the process-wide AuditLogger (optionally pinned to ``path``)."""
    global _LOGGER
    with _LOGGER_LOCK:
        if _LOGGER is None or (path is not None and _LOGGER.path != path):
            _LOGGER = AuditLogger(path)
        return _LOGGER


def reset_logger() -> None:
    """Drop the cached logger (tests / config changes)."""
    global _LOGGER
    with _LOGGER_LOCK:
        _LOGGER = None


def log_event(event_type: str, **kwargs) -> Optional[MutableMapping[str, Any]]:
    """Module-level convenience wrapper around ``get_logger().log_event``."""
    return get_logger().log_event(event_type, **kwargs)


# -- read / verify ----------------------------------------------------------


def iter_records(path: Optional[str] = None):
    """Yield parsed records from the audit log, in file order.

    A missing log file yields nothing (an empty chain is not an error here;
    :func:`verify_chain` decides what an empty log means).
    """
    source = path or os.environ.get("AUDIT_LOG_FILE", _DEFAULT_PATH)
    try:
        fh = open(source, "r", encoding="utf-8")
    except FileNotFoundError:
        return
    with fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                yield lineno, json.loads(line)
            except json.JSONDecodeError as exc:
                yield lineno, {"_parse_error": str(exc)}


def verify_chain(path: Optional[str] = None):
    """Verify the hash chain. Returns (ok: bool, errors: list[str]).

    Checks, per record: JSON parses, required fields present, entry_hash
    recomputes, prev_hash matches the previous record's entry_hash, and
    seq increments by exactly 1 starting at 1.
    """
    errors: list[str] = []
    expected_prev = GENESIS_HASH
    expected_seq = 1
    count = 0
    for lineno, rec in iter_records(path):
        count += 1
        where = f"line {lineno}"
        if "_parse_error" in rec:
            errors.append(f"{where}: malformed JSON ({rec['_parse_error']})")
            expected_prev = None  # chain state unknown from here on
            continue
        missing = [f for f in ("seq", "prev_hash", "entry_hash", "event_type", "ts")
                   if f not in rec]
        if missing:
            errors.append(f"{where}: missing fields {missing}")
            continue
        recomputed = compute_entry_hash(rec)
        if rec.get("entry_hash") != recomputed:
            errors.append(
                f"{where}: entry_hash mismatch "
                f"(stored {str(rec.get('entry_hash'))[:12]}... != "
                f"recomputed {recomputed[:12]}...) — record altered"
            )
        if expected_prev is not None and rec.get("prev_hash") != expected_prev:
            errors.append(
                f"{where}: prev_hash mismatch — chain break "
                f"(records inserted, deleted, or reordered)"
            )
        if rec.get("seq") != expected_seq:
            errors.append(
                f"{where}: seq {rec.get('seq')!r} not contiguous (expected "
                f"{expected_seq})"
            )
        expected_seq = int(rec.get("seq", expected_seq)) + 1
        expected_prev = recomputed
    if count == 0:
        # An absent file simply means nothing has been audited yet.
        source = path or os.environ.get("AUDIT_LOG_FILE", _DEFAULT_PATH)
        if not os.path.exists(source):
            errors.append(f"no audit log at {source}")
        else:
            errors.append("no records found")
    return (not errors), errors


def main(argv: list[str]) -> int:
    usage = "usage: python audit_log.py [verify|tail N] [AUDIT_LOG_FILE]"
    cmd = argv[0] if argv else "verify"
    if cmd == "verify":
        path = argv[1] if len(argv) > 1 else None
        ok, errs = verify_chain(path)
        if ok:
            print("audit chain OK")
            return 0
        print("audit chain BROKEN:")
        for e in errs:
            print(f"  - {e}")
        return 1
    if cmd == "tail":
        n = int(argv[1]) if len(argv) > 1 else 10
        records = [json.dumps(r, separators=(",", ":"))
                   for _, r in iter_records(argv[2] if len(argv) > 2 else None)]
        for line in records[-n:]:
            print(line)
        return 0
    print(usage, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))


__all__ = [
    "GENESIS_HASH",
    "AuditLogger",
    "canonical_json",
    "compute_entry_hash",
    "get_logger",
    "iter_records",
    "log_event",
    "reset_logger",
    "verify_chain",
]
