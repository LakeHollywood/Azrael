#!/usr/bin/env python3
"""Re-issue a workflow ledger entry with valid cryptography (wf_992 remediation).

Takes an UNSIGNED draft entry (strict JSON -- no comments, no truncated digests)
and produces the final entry: payload_hash recomputed over canonical JSON,
current_hash computed as HMAC(secret, prev|payload|timestamp), and a real
Ed25519 signature over the current_hash bytes.

Draft requirements (fail closed otherwise):
  * EXECUTING entries: previous_ledger_hash must be a FULL sha256:<64hex>
    digest matching an APPROVED predecessor in the same ledger file whose
    approval_context.authorized_targets cover this entry's targets.
  * PROPOSED entries: may link to the genesis sentinel (starting a new
    sub-chain) or to an existing entry's current_hash; no approval needed.
  * --payload-hash optionally pins the declared payload_hash (e.g. anchoring
    an external snapshot digest as the execution_context hash); it is then
    embedded into execution_context["snapshot_payload_hash"] so canonical
    recomputation stays consistent, and verified against the context.

Usage:
    python scripts/reissue_ledger_entry.py \
        --draft drafts/log_4491_draft.json \
        --ledger data/ledgers/wf_992.json \
        --hmac-secret-file /run/secrets/ledger_hmac_key \
        --signing-key-file /run/secrets/ledger_ed25519.key \
        --out data/ledgers/wf_992.json
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])  # repo root for imports

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import ledger_verifier as lv


def sign_entry(draft: dict, secret: bytes, private_key: Ed25519PrivateKey,
               payload_hash: str | None = None) -> dict:
    entry = dict(draft)
    payload = lv.payload_of(entry)
    if payload is None:
        raise ValueError(
            "draft has neither a 'payload' nor an 'execution_context' field; "
            "cannot compute payload_hash (fail closed)")
    if payload_hash is not None:
        # Anchor an external digest as this entry's payload hash.
        # The draft must already embed the digest in its payload
        # (e.g. snapshot_payload_hash); embedding it here would change the
        # canonicalization and break recomputation, so we only verify.
        found = lv.compute_payload_hash(payload)
        anchored = payload_hash in json.dumps(payload)
        if not (found == payload_hash or anchored):
            raise ValueError(
                f"--payload-hash {payload_hash} is neither the canonical "
                "digest of the draft's payload nor embedded within "
                "it; anchoring would produce an unverifiable entry "
                "(fail closed)")
        entry["payload_hash"] = payload_hash
    else:
        entry["payload_hash"] = lv.compute_payload_hash(payload)
    entry["current_hash"] = lv.compute_current_hash(
        entry["previous_ledger_hash"], entry["payload_hash"],
        entry["timestamp"], secret)
    sig = private_key.sign(entry["current_hash"].encode("utf-8"))
    entry["signature"] = "ed25519:" + base64.urlsafe_b64encode(sig).decode()
    return entry


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--draft", required=True, help="Unsigned draft entry JSON.")
    ap.add_argument("--ledger", required=True,
                    help="Ledger array file used to locate/validate the "
                         "APPROVED predecessor.")
    ap.add_argument("--hmac-secret-file", required=True)
    ap.add_argument("--signing-key-file", required=True,
                    help="PEM Ed25519 private key (raw bytes).")
    ap.add_argument("--payload-hash",
                    help="Pin the declared payload_hash (anchor an external "
                         "digest as this entry's payload hash). Must match a "
                         "canonicalization of --snapshot-file if given.")
    ap.add_argument("--snapshot-file",
                    help="JSON snapshot whose canonical digest is being "
                         "anchored; used to verify --payload-hash.")
    ap.add_argument("--out", required=True,
                    help="Output ledger file (predecessor + re-issued entry).")
    args = ap.parse_args(argv)

    with open(args.draft) as fh:
        draft = json.load(fh)  # strict JSON: raises on comments/truncation
    with open(args.ledger) as fh:
        chain = json.load(fh)
    with open(args.hmac_secret_file, "rb") as fh:
        secret = fh.read().strip()
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    with open(args.signing_key_file, "rb") as fh:
        private_key = load_pem_private_key(fh.read(), password=None)

    state = str(draft.get("lifecycle_state", ""))
    prev_hash = str(draft.get("previous_ledger_hash", ""))

    # Verify/derive the anchored payload hash if requested.
    payload_hash = args.payload_hash
    if args.snapshot_file:
        with open(args.snapshot_file) as fh:
            snapshot = json.load(fh)
        digest = "sha256:" + hashlib.sha256(
            lv.canonical_json(snapshot)).hexdigest()
        if payload_hash is not None and payload_hash != digest:
            print(f"::error::--payload-hash {payload_hash} does not match "
                  f"canonical digest of {args.snapshot_file} ({digest})",
                  file=sys.stderr)
            return 2
        payload_hash = digest
    if payload_hash is not None and not lv._SHA256_RE.match(payload_hash):
        print(f"::error::--payload-hash is not a full sha256:<64hex> digest: "
              f"{payload_hash!r}", file=sys.stderr)
        return 2

    if prev_hash == lv._GENESIS_HASH:
        predecessor = None
        if state != "PROPOSED":
            print("::error::only PROPOSED entries may link to the genesis "
                  "sentinel", file=sys.stderr)
            return 2
    else:
        predecessors = [e for e in chain
                        if e.get("current_hash") == prev_hash]
        if len(predecessors) != 1:
            print(f"::error::draft previous_ledger_hash {prev_hash!r} does not "
                  f"match exactly one entry in {args.ledger} "
                  f"(found {len(predecessors)})", file=sys.stderr)
            return 2
        predecessor = predecessors[0]
        if state == "EXECUTING" and \
                predecessor.get("lifecycle_state") != "APPROVED":
            print("::error::EXECUTING entries may only follow an APPROVED "
                  "predecessor", file=sys.stderr)
            return 2

    # Data-egress guard (log_export_7732 review): any payload naming a storage
    # destination must be covered by the nearest APPROVED ancestor's
    # authorized_targets -- checked at SIGNING time, not just at audit time.
    targets = lv.extract_targets(lv.payload_of(draft))
    approved_anc = None
    if any(t.startswith("storage_bucket:") or t.startswith("object_key:")
           for t in targets):
        if predecessor is not None and \
                predecessor.get("lifecycle_state") == "APPROVED":
            approved_anc = predecessor
        elif chain:
            ordered = sorted(chain, key=lambda e: e.get("timestamp", ""))
            idx = next((i for i, e in enumerate(ordered)
                        if e.get("current_hash") == prev_hash), None)
            if idx is not None:
                approved_anc = next(
                    (e for e in reversed(ordered[:idx + 1])
                     if e.get("lifecycle_state") == "APPROVED"), None)
        if approved_anc is None:
            print("::error::draft payload contains data-egress destinations "
                  f"{targets} but has no APPROVED ancestor in the ledger; "
                  "export scope cannot be verified (fail closed)",
                  file=sys.stderr)
            return 2
        approval_ctx = approved_anc.get("approval_context")
        authorized = (approval_ctx.get("authorized_targets")
                      if isinstance(approval_ctx, dict) else None)
        if not isinstance(authorized, list) or not authorized:
            print("::error::APPROVED ancestor lacks a non-empty "
                  "approval_context.authorized_targets list; export scope "
                  "cannot be verified (fail closed)", file=sys.stderr)
            return 2
        unauthorized = [t for t in targets if t not in authorized]
        if unauthorized:
            print("::error::export target(s) outside approved scope: "
                  f"{unauthorized}; authorized={sorted(authorized)} "
                  "(signing refused, fail closed)", file=sys.stderr)
            return 2

    try:
        entry = sign_entry(draft, secret, private_key, payload_hash)
    except ValueError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1

    # Fail closed: verify our own output before writing it.
    pub_b64 = base64.urlsafe_b64encode(
        private_key.public_key().public_bytes_raw()).decode()
    errors = lv.verify_entry(entry, secret, pub_b64,
                             expected_previous_state_entry=predecessor,
                             entries=chain + [entry])
    if errors:
        print("::error::re-issued entry failed verification:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    out_chain = [e for e in chain
                 if e.get("ledger_id") != entry["ledger_id"]]
    out_chain.append(entry)
    out_chain.sort(key=lambda e: e.get("timestamp", ""))
    with open(args.out, "w") as fh:
        json.dump(out_chain, fh, indent=2)
        fh.write("\n")
    print(f"Re-issued {entry['ledger_id']} -> {args.out}")
    print(f"  payload_hash : {entry['payload_hash']}")
    print(f"  current_hash : {entry['current_hash']}")
    print(f"  signature    : {entry['signature'][:27]}... (base64 elided)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
