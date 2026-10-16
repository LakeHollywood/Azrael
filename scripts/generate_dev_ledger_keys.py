#!/usr/bin/env python3
"""Generate local dev key material and re-issue sample ledgers with it.

This wires up the two files scripts/ledger_api_server.py's _dev_keys() reads:

    .ledgerdev/secret     raw HMAC-SHA256 secret bytes (shared MAC key)
    .ledgerdev/pub.b64    base64url Ed25519 PUBLIC key (root of trust)

and, because the committed sample ledgers in data/ledgers/ were signed with
key material that is not recoverable from this repository, it re-issues every
entry in those ledgers against the freshly generated keys -- exactly the
remediation path scripts/reissue_ledger_entry.py documents, applied to whole
chains instead of single drafts:

  * payload_hash is recomputed over canonical JSON of each entry's payload
    (payload_of(): "payload" if present, else "execution_context"), so no
    declared digest can silently drift from its content;
  * current_hash = HMAC(secret, "prev|payload|timestamp") via
    ledger_verifier.compute_current_hash;
  * signature = ed25519:<base64url(priv.sign(current_hash bytes))>.

Chain linkage, lifecycle transitions, approval scope, and the data-egress
guard are all re-checked with ledger_verifier.verify_chain before anything is
written; a chain that fails verification after re-issuance aborts without
touching the file (fail closed).

Safety / secret hygiene:
  * The private Ed25519 key is written ONLY to .ledgerdev/ed25519.key (mode
    0600); .ledgerdev/ is denylisted by scripts/secret_scan.py and must never
    be committed. CI does not use these files: the ledger-audit-gate workflow
    injects LEDGER_HMAC_SECRET_B64 / LEDGER_ED25519_PUBKEY_B64 from the
    environment's secrets/vars instead.
  * If key files already exist they are reused (idempotent), unless --rotate.

Usage:
    python scripts/generate_dev_ledger_keys.py            # create keys + reissue
    python scripts/generate_dev_ledger_keys.py --rotate   # fresh keys, reissue
    python scripts/generate_dev_ledger_keys.py --keys-only
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import stat
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
    load_pem_private_key,
)

import ledger_verifier as lv

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEV_DIR = os.path.join(_ROOT, ".ledgerdev")
SECRET_FILE = os.path.join(DEV_DIR, "secret")
PUBKEY_FILE = os.path.join(DEV_DIR, "pub.b64")
PRIVATE_KEY_FILE = os.path.join(DEV_DIR, "ed25519.key")

DEFAULT_LEDGERS = [
    os.path.join(_ROOT, "data", "ledgers", "wf_992.json"),
    os.path.join(_ROOT, "data", "ledgers", "export_job_9912.json"),
]


def _write_private(path: str, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(b"")


def ensure_keys(rotate: bool) -> tuple[bytes, Ed25519PrivateKey]:
    """Load existing dev keys or generate them; returns (secret, private_key)."""
    os.makedirs(DEV_DIR, exist_ok=True)
    have_all = all(os.path.isfile(p) for p in
                   (SECRET_FILE, PUBKEY_FILE, PRIVATE_KEY_FILE))
    if have_all and not rotate:
        with open(SECRET_FILE, "rb") as fh:
            secret = fh.read().strip()
        with open(PRIVATE_KEY_FILE, "rb") as fh:
            private_key = load_pem_private_key(fh.read(), password=None)
        _check_pubkey_matches(private_key)
        print(f"[dev-keys] reusing existing key material in {DEV_DIR}/")
        return secret, private_key

    secret = secrets.token_bytes(32)
    private_key = Ed25519PrivateKey.generate()
    pub = private_key.public_key().public_bytes_raw()
    pub_b64 = base64.urlsafe_b64encode(pub).decode("ascii")

    for path, data in ((SECRET_FILE, secret),
                       (PRIVATE_KEY_FILE,
                        private_key.private_bytes(
                            Encoding.PEM, PrivateFormat.PKCS8,
                            NoEncryption())),
                       (PUBKEY_FILE, pub_b64.encode("ascii"))):
        _write_private(path, 0o600 if path != PUBKEY_FILE else 0o644)
        with open(path, "wb") as fh:
            fh.write(data)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR
                 if path != PUBKEY_FILE else 0o644)
    action = "rotated" if have_all else "generated"
    print(f"[dev-keys] {action} key material in {DEV_DIR}/ "
          f"(pubkey b64: {pub_b64[:16]}...)")
    return secret, private_key


def _check_pubkey_matches(private_key) -> None:
    with open(PUBKEY_FILE, "r", encoding="utf-8") as fh:
        stored = fh.read().strip()
    actual = base64.urlsafe_b64encode(
        private_key.public_key().public_bytes_raw()).decode("ascii")
    if stored != actual:
        raise SystemExit("[dev-keys] FATAL: .ledgerdev/pub.b64 does not match "
                         ".ledgerdev/ed25519.key; run with --rotate")


def reissue_ledger(path: str, secret: bytes, private_key) -> bool:
    """Re-sign one ledger file in place. Returns True if it changed."""
    with open(path, "r", encoding="utf-8") as fh:
        entries = json.load(fh)
    if not isinstance(entries, list):
        raise SystemExit(f"[reissue] FATAL: {path} is not a JSON array")

    updated = []
    prev_entry = None
    for i, e in enumerate(entries):
        entry = dict(e)
        payload = lv.payload_of(entry)
        if payload is None:
            raise SystemExit(f"[reissue] FATAL: {path} entry "
                             f"{entry.get('ledger_id')!r} has no payload")
        # Re-link the chain: previous_ledger_hash must name the predecessor's
        # NEW current_hash (the old digests die with the old HMAC secret).
        # Position 0 keeps its declared value -- verify_chain enforces it
        # equals the genesis sentinel, so a bad genesis link fails closed.
        if i > 0:
            entry["previous_ledger_hash"] = prev_entry["current_hash"]
        entry["payload_hash"] = lv.compute_payload_hash(payload)
        entry["current_hash"] = lv.compute_current_hash(
            entry["previous_ledger_hash"], entry["payload_hash"],
            entry["timestamp"], secret)
        sig = private_key.sign(entry["current_hash"].encode("utf-8"))
        entry["signature"] = "ed25519:" + base64.urlsafe_b64encode(
            sig).decode("ascii")
        updated.append(entry)
        prev_entry = entry

    # Fail closed: refuse to write a chain that does not verify end-to-end.
    pub_b64 = base64.urlsafe_b64encode(
        private_key.public_key().public_bytes_raw()).decode("ascii")
    errors = lv.verify_chain(updated, secret, pub_b64)
    if errors:
        print(f"[reissue] REFUSING to write {path}: re-issued chain failed "
              "verification:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        raise SystemExit(2)

    if updated == entries:
        print(f"[reissue] {os.path.relpath(path, _ROOT)}: already valid, "
              "unchanged")
        return False
    text = json.dumps(updated, indent=2) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"[reissue] {os.path.relpath(path, _ROOT)}: re-signed "
          f"{len(updated)} entr{'y' if len(updated) == 1 else 'ies'} "
          "(chain verified)")
    return True


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rotate", action="store_true",
                    help="Discard existing dev keys and generate fresh ones.")
    ap.add_argument("--keys-only", action="store_true",
                    help="Create/reuse key material but do not touch ledgers.")
    ap.add_argument("--ledger", action="append", dest="ledgers",
                    help="Ledger file to re-issue (repeatable; defaults to "
                         "data/ledgers/wf_992.json and export_job_9912.json).")
    args = ap.parse_args(argv)

    secret, private_key = ensure_keys(args.rotate)
    if args.keys_only:
        return 0
    changed = 0
    for path in args.ledgers or DEFAULT_LEDGERS:
        if not os.path.isfile(path):
            print(f"[reissue] skipping missing ledger {path}", file=sys.stderr)
            continue
        if reissue_ledger(path, secret, private_key):
            changed += 1
    print(f"[reissue] done ({changed} file(s) rewritten); "
          "verify locally with: python ledger_verifier.py verify-ledger "
          "--ledger <file> --hmac-secret-file .ledgerdev/secret "
          f"--pubkey-b64 $(cat {PUBKEY_FILE})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
