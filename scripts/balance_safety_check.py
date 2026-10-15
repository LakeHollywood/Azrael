#!/usr/bin/env python3
"""Fail-closed balance-safety check for financial tx payloads (tx-1 incident).

Replays the proposed transaction against the anchored acme snapshot in
data/ledgers/wf_992.json (log_4492) and refuses to produce a signable draft
when the resulting balance would be negative.

Usage:
    python drafts/tx_1_overdraft_check.py --tx '{"id":"tx-1",...}' \
        [--ledger data/ledgers/wf_992.json] [--entry-id log_4492]
Exit codes: 0 = balance-safe, draft emitted; 2 = OVERDRAFT, no draft.
"""
import argparse, json, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import ledger_verifier as lv


def balances_from_snapshot(execution_context):
    out = {}
    for acct in execution_context.get("accounts", []):
        bal = acct.get("balance", {})
        amt = bal.get("amount")
        if isinstance(amt, (int, float)) and not isinstance(amt, bool):
            out[acct["id"]] = {"amount": int(amt), "currency": bal.get("currency")}
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--tx", required=True, help="Transaction JSON payload.")
    ap.add_argument("--ledger", default="data/ledgers/wf_992.json")
    ap.add_argument("--entry-id", default="log_4492")
    ap.add_argument("--out", default="drafts/tx_1_draft.json")
    args = ap.parse_args(argv)

    tx = json.loads(args.tx)  # strict JSON, fail closed on garbage
    amount = tx.get("amount")
    if not isinstance(amount, (int, float)) or isinstance(amount, bool):
        print("::error::tx.amount missing or non-numeric (fail closed)", file=sys.stderr)
        return 2
    amount = int(amount)
    account_id = tx.get("accountId")

    chain = json.load(open(args.ledger))
    entry = next((e for e in chain if e.get("ledger_id") == args.entry_id), None)
    if entry is None:
        print(f"::error::anchor entry {args.entry_id} not found in {args.ledger}", file=sys.stderr)
        return 2
    # Verify the anchor's payload hash before trusting its balances.
    recomputed = lv.compute_payload_hash(entry["execution_context"])
    if recomputed != entry["payload_hash"]:
        print(f"::error::anchor payload_hash mismatch ({recomputed} != "
              f"{entry['payload_hash']}); refusing to use stale/tampered snapshot",
              file=sys.stderr)
        return 2

    tx_digest = lv._digest(lv.canonical_json(tx))
    balances = balances_from_snapshot(entry["execution_context"])
    if account_id not in balances:
        print(f"::error::account {account_id!r} not present in anchored snapshot "
              "(fail closed)", file=sys.stderr)
        return 2
    pre = balances[account_id]
    if pre["currency"] != "USD":
        print(f"::error::snapshot currency {pre['currency']!r} != expected USD "
              "(fail closed)", file=sys.stderr)
        return 2
    post = pre["amount"] + amount  # signed delta convention: withdrawals are negative
    overdrawn = post < 0
    currency = pre["currency"]

    report = {
        "tx_id": tx.get("id"),
        "tx_payload_hash": tx_digest,
        "anchored_in": {"ledger_id": entry["ledger_id"],
                        "payload_hash": entry["payload_hash"]},
        "account": account_id,
        "currency": currency,
        "pre_balance": pre["amount"],
        "delta": amount,
        "post_balance": post,
        "verdict": "OVERDRAFT_BLOCKED" if overdrawn else "BALANCE_SAFE",
    }
    if abs(post - pre["amount"]) >= 2 * abs(pre["amount"]) and pre["amount"] > 0:
        report["unit_convention_flag"] = ("|delta| >= 2x balance: minor-vs-major-unit "
                                          "ambiguity suspected; confirm cents vs dollars")
    # Machine-readable report on stdout (single JSON document); human notes on stderr.
    print(json.dumps(report, indent=2))

    if overdrawn:
        print(f"::error::OVERDRAFT: {account_id} would go to {post} {currency} "
              f"(balance {pre['amount']} {currency}, delta {amount}). No draft "
              "emitted; dual_approval gate + overdraft control must clear first.",
              file=sys.stderr)
        return 2

    draft = {
        "ledger_id": f"log_tx_{tx.get('id')}",
        "workflow_id": "wf_992",
        "lifecycle_state": "PROPOSED",
        "timestamp": "2026-10-15T15:05:00Z",
        "previous_ledger_hash": entry["current_hash"],
        "execution_context": {
            "transaction": tx,
            "target_account": account_id,
            "tx_payload_hash": tx_digest,
            "anchored_snapshot_hash": entry["payload_hash"],
        },
    }
    json.dump(draft, open(args.out, "w"), indent=2)
    print(f"# balance-safe; PROPOSED draft written to {args.out} (unsigned; requires "
          f"an APPROVED predecessor with authorized_targets covering {account_id!r} "
          "before EXECUTING)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
