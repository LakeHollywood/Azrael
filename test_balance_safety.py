"""Tests for scripts/balance_safety_check.py (tx-1 overdraft incident)."""
import json, subprocess, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parent
SCRIPT = ROOT / "scripts" / "balance_safety_check.py"


def run(tx, out_file=None):
    args = [sys.executable, str(SCRIPT), "--tx", json.dumps(tx)]
    if out_file:
        args += ["--out", out_file]
    p = subprocess.run(args, capture_output=True, text=True)
    # stdout: report JSON; stderr: human notes/errors; draft (if any) at out_file
    return p.returncode, p.stdout, p.stderr


def test_overdraft_blocked_exit2():
    rc, out, err = run({"id": "tx-1", "accountId": "cash",
                        "amount": -150000, "description": "Big withdrawal"})
    assert rc == 2
    report = json.loads(out)
    assert report["verdict"] == "OVERDRAFT_BLOCKED"
    assert report["pre_balance"] == 100000 and report["post_balance"] == -50000
    assert "OVERDRAFT" in err


def test_tx_payload_hash_is_canonical_digest():
    tx = {"id": "tx-1", "accountId": "cash", "amount": -150000,
          "description": "Big withdrawal"}
    rc, out, _ = run(tx)
    import ledger_verifier as lv
    assert rc == 2
    assert json.loads(out)["tx_payload_hash"] == lv._digest(lv.canonical_json(tx))


def test_safe_withdrawal_emits_draft(tmp_path=None):
    import tempfile, os
    d = tempfile.mkdtemp()
    out_file = os.path.join(d, "draft.json")
    rc, out, err = run({"id": "tx-ok", "accountId": "cash", "amount": -40000,
                        "description": "ok"}, out_file=out_file)
    assert rc == 0, err
    assert json.loads(out)["verdict"] == "BALANCE_SAFE"
    draft = json.load(open(out_file))
    assert draft["lifecycle_state"] == "PROPOSED"
    # draft links onto the anchored snapshot entry's current_hash
    chain = json.load(open(ROOT / "data" / "ledgers" / "wf_992.json"))
    anchor = next(e for e in chain if e["ledger_id"] == "log_4492")
    assert draft["previous_ledger_hash"] == anchor["current_hash"]
    assert draft["execution_context"]["anchored_snapshot_hash"] == anchor["payload_hash"]


def test_unknown_account_fails_closed():
    rc, _, err = run({"id": "tx-x", "accountId": "savings", "amount": -1})
    assert rc == 2 and "not present in anchored snapshot" in err


def test_nonnumeric_amount_fails_closed():
    rc, _, err = run({"id": "tx-y", "accountId": "cash", "amount": "-150000"})
    assert rc == 2 and "non-numeric" in err


def test_bool_amount_rejected():
    rc, _, err = run({"id": "tx-z", "accountId": "cash", "amount": True})
    assert rc == 2


def test_near_total_drain_is_safe_unflagged():
    # -90000 leaves +10000 USD: balance-safe, and |delta| < 2x balance so no unit flag
    import tempfile, os
    d = tempfile.mkdtemp()
    out_file = os.path.join(d, "u.json")
    rc, out, err = run({"id": "tx-u", "accountId": "cash", "amount": -90000,
                        "description": "near-total drain"}, out_file=out_file)
    report = json.loads(out)
    assert rc == 0 and report["post_balance"] == 10000
    assert "unit_convention_flag" not in report
    assert json.load(open(out_file))["lifecycle_state"] == "PROPOSED"

def test_unit_convention_flag_on_overdrawing_delta():
    # |delta| >= 2x balance can only occur alongside overdraft (pre>0): tx-1 itself
    rc, out, _ = run({"id": "tx-v", "accountId": "cash", "amount": -250000,
                      "description": "double-the-account withdrawal"})
    report = json.loads(out)
    assert rc == 2
    assert report["verdict"] == "OVERDRAFT_BLOCKED"
    assert "unit_convention_flag" in report
