#!/usr/bin/env python3
"""Re-issue a workflow ledger entry with valid cryptography (wf_992 remediation).

Takes an UNSIGNED draft entry (strict JSON -- no comments, no truncated digests)
and produces the final entry: payload_hash recomputed over canonical JSON,
current_hash computed as HMAC(secret, prev|payload|timestamp), and a real
Ed25519 signature over the current_hash bytes.

Draft requirements (fail closed otherwise):
  * previous_ledger_hash must be a FULL sha256:<64hex> digest matching the
    APPROVED predecessor's current_hash.
  * The APPROVED predecessor must exist in the same ledger file and enumerate
    approval_context.authorized_targets covering this entry's targets.

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
import json
import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])  # repo root for imports

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import ledger_verifier as lv


def sign_entry(draft: dict, secret: bytes, private_key: Ed25519PrivateKey) -> dict:
    entry = dict(draft)
    entry["payload_hash"] = lv.compute_payload_hash(entry["execution_context"])
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

    prev_hash = str(draft.get("previous_ledger_hash", ""))
    predecessors = [e for e in chain
                    if e.get("current_hash") == prev_hash]
    if len(predecessors) != 1:
        print(f"::error::draft previous_ledger_hash {prev_hash!r} does not "
              f"match exactly one entry in {args.ledger} "
              f"(found {len(predecessors)})", file=sys.stderr)
        return 2
    predecessor = predecessors[0]
    if predecessor.get("lifecycle_state") != "APPROVED":
        print("::error::EXECUTING entries may only follow an APPROVED "
              "predecessor", file=sys.stderr)
        return 2

    entry = sign_entry(draft, secret, private_key)

    # Fail closed: verify our own output before writing it.
    pub_b64 = base64.urlsafe_b64encode(
        private_key.public_key().public_bytes_raw()).decode()
    errors = lv.verify_entry(entry, secret, pub_b64,
                             expected_previous_state_entry=predecessor)
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
