"""Fail-closed cryptographic verifier for workflow ledger entries.

Verifies a single ledger entry of the form:

    {
      "ledger_id": "...", "workflow_id": "...", "lifecycle_state": "...",
      "timestamp": "...", "previous_ledger_hash": "sha256:<64 hex>",
      "execution_context": {...}, "payload_hash": "sha256:<64 hex>",
      "current_hash": "sha256:<64 hex>",   # HMAC(secret, prev|payload|ts)
      "signature": "ed25519:<base64>"       # Ed25519 over current_hash bytes
    }

Design notes (from the log_4491 review):
  * Hashes must be FULL digests - truncated ("8f7d...") or annotated values fail.
  * payload_hash is computed over canonical JSON (sorted keys, compact separators)
    so serialization ambiguity cannot break verification.
  * HMAC input is a CANONICALIZATION-EXPLICIT string: "prev|payload|timestamp".
  * Ed25519 signature is the root of trust and is verified over the current_hash
    digest bytes; HMAC alone only proves knowledge of a shared secret.
  * State transitions are enforced: EXECUTING may only follow APPROVED.
  * Scope enforcement (wf_992 remediation): an APPROVED predecessor MUST carry an
    `approval_context` whose `authorized_targets` list enumerates every target
    the approval covers. Any successor whose execution_context targets something
    outside that list is rejected -- no implicit scope inheritance.

CLI (used by the CI compliance gate, exit code != 0 on any failure):

    python ledger_verifier.py verify-ledger \
        --ledger path/to/ledger.json \
        --entry-id log_4491 \
        --hmac-secret-file /run/secrets/ledger_hmac_key \
        --pubkey-b64 "$LEDGER_ED25519_PUBKEY_B64"
"""

import argparse
import hashlib
import hmac
import json
import re
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:  # pragma: no cover
    Ed25519PublicKey = None
    InvalidSignature = Exception

import base64

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ALLOWED_TRANSITIONS = {
    "PROPOSED": {"APPROVED", "REJECTED"},
    "APPROVED": {"EXECUTING", "ABORTED"},
    "EXECUTING": {"COMPLETED", "FAILED", "RESOLVED", "ABORTED"},
    # COMPLETED / FAILED / RESOLVED / REJECTED / ABORTED are terminal:
    # absent from the mapping's keys, so nothing may follow them.
}

# States that close a workflow; no successor entry is legal from these.
TERMINAL_STATES = frozenset(
    {"COMPLETED", "FAILED", "RESOLVED", "REJECTED", "ABORTED"})

# A new chain's first entry links to this sentinel instead of a predecessor.
_GENESIS_HASH = "sha256:" + "0" * 64


class LedgerVerificationError(Exception):
    pass


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_payload_hash(execution_context) -> str:
    return _digest(canonical_json(execution_context))


def compute_current_hash(previous_ledger_hash: str, payload_hash: str,
                         timestamp: str, secret: bytes) -> str:
    message = f"{previous_ledger_hash}|{payload_hash}|{timestamp}".encode("utf-8")
    mac = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return "sha256:" + mac


# Field names that denote WHERE data lands or originates -- these are
# authorization-relevant just like explicit "target_*" fields.  Export/data-
# egress payloads (see log_export_7732) name their destination storage_bucket
# and object_key instead of target_cluster; without this list, such entries
# would carry zero extracted targets and silently pass the scope check.
_DESTINATION_FIELD_NAMES = ("storage_bucket", "object_key")


def _walk_dict_nodes(obj, path=()):
    """Yield (path, dict) for every nested dict inside obj."""
    if isinstance(obj, dict):
        yield path, obj
        for key, value in obj.items():
            yield from _walk_dict_nodes(value, path + (key,))


def extract_targets(execution_context) -> list[str]:
    """Pull every authorization-relevant locator out of an execution context.

    Two families of fields are treated as targets so new tools cannot silently
    bypass scope checks by inventing a differently-named field:

    * Any key matching /target/ at ANY nesting depth (e.g. target_cluster,
      target_gateway).
    * Data-egress destinations: keys named ``storage_bucket`` or ``object_key``
      at any depth (an export writes exactly where those point).  They are
      returned prefixed (``storage_bucket:<v>`` / ``object_key:<v>``) so an
      APPROVED predecessor must enumerate authorized values in the same
      prefixed form -- fail closed on typos or missing declarations.
    """
    targets = []
    for _path, node in _walk_dict_nodes(execution_context):
        for key, value in node.items():
            lname = key.lower()
            if "target" in lname:
                if isinstance(value, list):
                    targets.extend(str(v) for v in value)
                else:
                    targets.append(str(value))
            elif lname in _DESTINATION_FIELD_NAMES:
                if isinstance(value, list):
                    targets.extend(f"{lname}:{v}" for v in value)
                else:
                    targets.append(f"{lname}:{value}")
    return sorted(set(targets))


def payload_of(entry: dict):
    """Return an entry's payload in canonical form.

    Newer entries (e.g. log_export_7732) name the field ``payload``; the wf_992
    convention uses ``execution_context``.  Both are accepted so scope checks
    cover closure payloads regardless of naming.
    """
    if "payload" in entry:
        return entry["payload"]
    return entry.get("execution_context")


def _find_approved_ancestor(entries: list[dict], entry: dict) -> dict | None:
    """Nearest APPROVED entry preceding ``entry`` in the chain (by position).

    ``entry`` need not itself be present in ``entries`` (e.g. an unsigned
    draft): the scan starts at the last entry whose timestamp is strictly
    earlier than ``entry``'s, or from the end of the list when ``entry`` is
    absent.  Entries sharing ``entry``'s ledger_id are excluded.
    """
    ts = str(entry.get("timestamp", ""))
    candidates = [e for e in entries
                  if e.get("ledger_id") != entry.get("ledger_id")
                  and str(e.get("timestamp", "")) < ts] or list(entries)
    for e in reversed(candidates):
        if isinstance(e, dict) and e.get("lifecycle_state") == "APPROVED":
            return e
    return None


def verify_entry(entry: dict, hmac_secret: bytes, ed25519_pubkey_b64: str,
                 expected_previous_state_entry: dict | None = None,
                 entries: list[dict] | None = None) -> list[str]:
    """Return a list of failure reasons. Empty list == entry is valid.

    ``entries`` optionally supplies the full chain (oldest first) so closure
    states (RESOLVED/COMPLETED) can locate their APPROVED ancestor for scope
    checking; without it that check is skipped here and enforced by
    verify_chain(), which always passes the list.
    """
    errors = []

    # --- structural checks -------------------------------------------------
    required = ("ledger_id", "workflow_id", "lifecycle_state", "timestamp",
                "previous_ledger_hash", "payload_hash",
                "current_hash", "signature")
    for field in required:
        if field not in entry:
            errors.append(f"missing field: {field}")
    # Payload may be named either way (log_export_7732 uses "payload"; the
    # wf_992 convention uses "execution_context").  At least one is required.
    if "payload" not in entry and "execution_context" not in entry:
        errors.append("missing field: payload (or execution_context)")
    if errors:
        return errors

    # --- full-digest format checks (fail closed on truncation) ------------
    for field in ("previous_ledger_hash", "payload_hash", "current_hash"):
        if not _SHA256_RE.match(str(entry[field])):
            errors.append(f"{field} is not a full sha256:<64hex> digest: "
                          f"{entry[field]!r}")

    sig = str(entry["signature"])
    if not sig.startswith("ed25519:"):
        errors.append("signature must use 'ed25519:' scheme")

    if errors:
        return errors  # cannot safely continue

    # --- payload hash recomputation ---------------------------------------
    # Convention: payload_hash is the canonical digest of payload_of(entry)
    # (``payload`` if present, else ``execution_context``).
    recomputed_payload = compute_payload_hash(payload_of(entry))
    if not hmac.compare_digest(recomputed_payload, entry["payload_hash"]):
        errors.append(f"payload_hash mismatch: recomputed {recomputed_payload} "
                      f"!= declared {entry['payload_hash']}")

    # --- HMAC chain link ---------------------------------------------------
    recomputed_current = compute_current_hash(
        entry["previous_ledger_hash"], entry["payload_hash"],
        entry["timestamp"], hmac_secret)
    if not hmac.compare_digest(recomputed_current, entry["current_hash"]):
        errors.append("current_hash HMAC mismatch (canonicalization: "
                      "prev|payload|timestamp)")

    # --- ed25519 root of trust ---------------------------------------------
    # Convention: signature = ed25519:<base64url(priv.sign(current_hash))>.
    # The public key itself is supplied out-of-band via `ed25519_pubkey_b64`;
    # it is NOT embedded in the signature field.
    if Ed25519PublicKey is None:
        errors.append("cryptography package unavailable; cannot verify "
                      "ed25519 signature (fail closed)")
    else:
        try:
            pub = Ed25519PublicKey.from_public_bytes(
                base64.urlsafe_b64decode(ed25519_pubkey_b64.encode()))
            signature_bytes = base64.urlsafe_b64decode(
                sig[len("ed25519:"):].encode())
            pub.verify(signature_bytes, entry["current_hash"].encode("utf-8"))
        except (InvalidSignature, ValueError) as exc:
            errors.append(f"ed25519 signature invalid: {exc}")

    # --- lifecycle transition check -----------------------------------------
    state = entry["lifecycle_state"]
    if expected_previous_state_entry is not None:
        prev_state = expected_previous_state_entry.get("lifecycle_state")
        allowed = _ALLOWED_TRANSITIONS.get(prev_state, set())
        if state not in allowed:
            errors.append(f"illegal transition {prev_state} -> {state}")
        if not hmac.compare_digest(expected_previous_state_entry["current_hash"],
                                   entry["previous_ledger_hash"]):
            errors.append("previous_ledger_hash does not match predecessor's "
                          "current_hash (chain break)")

        # --- authorization-scope check (wf_992 remediation) -----------------
        # Any executed action must fall inside the targets enumerated by the
        # APPROVED predecessor. Fail closed: an APPROVED entry without an
        # explicit authorized_targets list authorizes NOTHING.
        if prev_state == "APPROVED":
            approval_ctx = expected_previous_state_entry.get("approval_context")
            authorized = (approval_ctx.get("authorized_targets")
                          if isinstance(approval_ctx, dict) else None)
            if not isinstance(authorized, list) or not authorized:
                errors.append(
                    "APPROVED predecessor lacks a non-empty "
                    "approval_context.authorized_targets list; execution scope "
                    "cannot be verified (fail closed)")
            else:
                unauthorized = [t for t in extract_targets(
                    entry.get("execution_context")) if t not in authorized]
                if unauthorized:
                    errors.append(
                        "target(s) outside approved scope: "
                        f"{unauthorized}; authorized={sorted(authorized)}")

    # --- closure-state scope check ------------------------------------------
    # RESOLVED/COMPLETED entries carry the *result* of execution (e.g. an
    # export's destination bucket).  Their immediate predecessor is usually
    # EXECUTING, so the prev_state == "APPROVED" branch above never sees them.
    # A data-egress result naming an unauthorized storage_bucket would slip
    # through unless we walk back to the nearest APPROVED ancestor and enforce
    # its authorized_targets over the closure payload too.  Only enforced when
    # a full-chain context is available (entries); standalone verification of
    # a single closure entry cannot locate an ancestor, which is why the CI
    # gate runs verify_chain(), not verify_entry(), whenever possible.
    if state in ("RESOLVED", "COMPLETED") and entries is not None:
        approved_ancestor = _find_approved_ancestor(entries, entry)
        if approved_ancestor is not None:
            approval_ctx = approved_ancestor.get("approval_context")
            authorized = (approval_ctx.get("authorized_targets")
                          if isinstance(approval_ctx, dict) else None)
            if not isinstance(authorized, list) or not authorized:
                errors.append(
                    f"{state} entry's APPROVED ancestor lacks a non-empty "
                    "approval_context.authorized_targets list; result scope "
                    "cannot be verified (fail closed)")
            else:
                unauthorized = [t for t in extract_targets(payload_of(entry))
                                if t not in authorized]
                if unauthorized:
                    errors.append(
                        f"{state} result target(s) outside approved scope: "
                        f"{unauthorized}; authorized={sorted(authorized)}")
        elif expected_previous_state_entry is not None \
                and expected_previous_state_entry.get(
                    "lifecycle_state") != "APPROVED":
            errors.append(
                f"{state} entry has no APPROVED ancestor in the chain; "
                "result scope cannot be verified (fail closed)")

    return errors


def verify_chain(entries: list[dict], hmac_secret: bytes,
                 ed25519_pubkey_b64: str,
                 genesis_previous_hash: str = _GENESIS_HASH) -> list[str]:
    """Verify a whole ledger chain, oldest entry first.

    Checks every entry cryptographically AND verifies linkage: each entry's
    previous_ledger_hash must equal its predecessor's current_hash (the first
    entry must link to the genesis sentinel). Returns failure reasons with an
    entry-index prefix; empty list == chain valid.
    """
    errors = []
    prev_entry = None
    for i, entry in enumerate(entries):
        errs = verify_entry(entry, hmac_secret, ed25519_pubkey_b64,
                            expected_previous_state_entry=prev_entry,
                            entries=entries)
        expected_prev = (prev_entry["current_hash"] if prev_entry
                         else genesis_previous_hash)
        declared_prev = str(entry.get("previous_ledger_hash", ""))
        if not hmac.compare_digest(declared_prev, expected_prev):
            errs.append(f"chain linkage broken at position {i}: "
                        f"previous_ledger_hash {declared_prev!r} != "
                        f"expected {expected_prev!r}")
        if errs:
            errors.extend(f"[{i}:{entry.get('ledger_id', '?')}] {e}"
                          for e in errs)
        prev_entry = entry
    return errors


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail-closed ledger verification (CI compliance gate).")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("verify-ledger",
                       help="Verify one entry (and optionally its chain).")
    p.add_argument("--ledger", required=True,
                   help="JSON file: a single entry object, or an array of "
                        "entries ordered oldest-first.")
    p.add_argument("--entry-id",
                   help="ledger_id to verify within the array (requires its "
                        "immediate predecessor in the same file).")
    sec = p.add_mutually_exclusive_group(required=True)
    sec.add_argument("--hmac-secret-file",
                     help="File containing the raw HMAC shared secret.")
    sec.add_argument("--hmac-secret-b64",
                     help="Base64 of the raw HMAC shared secret.")
    pub = p.add_mutually_exclusive_group(required=True)
    pub.add_argument("--pubkey-b64",
                     help="Base64url Ed25519 public key (root of trust).")
    pub.add_argument("--pubkey-file",
                     help="File containing the base64url Ed25519 public key.")
    args = parser.parse_args(argv)

    try:
        with open(args.ledger, "rb") as fh:
            data = json.load(fh)
        if args.hmac_secret_file:
            with open(args.hmac_secret_file, "rb") as fh:
                secret = fh.read().strip()
        else:
            secret = base64.b64decode(args.hmac_secret_b64)
        pubkey_b64 = (args.pubkey_b64 or
                      open(args.pubkey_file).read().strip())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"::error::ledger verifier input error: {exc}", file=sys.stderr)
        return 2

    if isinstance(data, dict):
        entries = [data]
    elif isinstance(data, list):
        entries = data
    else:
        print("::error::ledger file must contain a JSON object or array",
              file=sys.stderr)
        return 2

    if args.entry_id:
        ids = [e.get("ledger_id") for e in entries]
        if args.entry_id not in ids:
            print(f"::error::{args.entry_id} not found in ledger",
                  file=sys.stderr)
            return 1
        idx = ids.index(args.entry_id)
        target = entries[idx]
        predecessor = entries[idx - 1] if idx > 0 else None
        if predecessor is None and target.get("lifecycle_state") != "PROPOSED":
            print(f"::error::{args.entry_id} has no predecessor in the file; "
                  "its approval scope cannot be verified (fail closed)",
                  file=sys.stderr)
            return 1
        errors = verify_entry(target, secret, pubkey_b64,
                              expected_previous_state_entry=predecessor)
    else:
        errors = verify_chain(entries, secret, pubkey_b64)

    if errors:
        print(f"::error::ledger verification FAILED "
              f"({len(errors)} problem(s)):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print("Ledger verification passed: digests full, canonical hashes match, "
          "ed25519 signature valid, transitions and approval scope enforced.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
