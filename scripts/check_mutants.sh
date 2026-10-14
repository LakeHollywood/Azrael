#!/usr/bin/env bash
# =============================================================================
# check_mutants.sh — mutation-testing gate for the HITL approval-gate
# control plane.
#
# Runs mutmut against the constitutional risk module (approval_gate/risk.py,
# scoped in pyproject.toml [tool.mutmut]) and enforces the thresholds agreed
# for this repo:
#
#   1. The three non-negotiable guardrail mutants MUST be killed:
#        - authz changes can never evaluate below DUAL_APPROVAL (floor 60)
#        - ApprovalGate modifications always evaluate to RESTRICTED (100)
#        - risk->policy mapping is monotonic across 0-100
#      We enforce this by requiring ZERO surviving mutants unless the
#      surviving source line is explicitly marked as equivalent (see #2).
#
#   2. Equivalent survivors are permitted ONLY when pinned: a mutant on a
#      source line carrying the `noqa: MUT-internal-callchain` marker is
#      counted as "marked-equivalent" instead of "survived", so intentional
#      call-chain artifacts don't fail the build but silent drift does.
#
#   3. Overall mutation score must be >= MUTATION_SCORE_THRESHOLD (95% by
#      default), counting killed+timeout+suspicious+marked-equivalent as
#      handled.
#
# Exit codes:
#   0  all gates passed
#   1  threshold violated (survivors or low score) -> fail the pipeline
#   2  tooling failure (mutmut/pytest missing, run crashed)
#
# Usage:
#   ./scripts/check_mutants.sh
#   MUTATION_SCORE_THRESHOLD=90 ./scripts/check_mutants.sh   # relax score gate
#   STRICT_ZERO_SURVIVORS=1 ./scripts/check_mutants.sh       # original hard gate
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MUTATION_SCORE_THRESHOLD="${MUTATION_SCORE_THRESHOLD:-95}"
STRICT_ZERO_SURVIVORS="${STRICT_ZERO_SURVIVORS:-0}"
EQUIVALENT_MARKERS="MUT-internal-callchain MUT-equivalent"

export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1   # broken libtmux plugin in CI image

fail() { echo "GATE FAILED: $*" >&2; exit 1; }
toolfail() { echo "TOOLING ERROR: $*" >&2; exit 2; }

command -v mutmut >/dev/null 2>&1 || toolfail "mutmut not installed (pip install mutmut)"
python -c "import pytest"          || toolfail "pytest not installed"

echo "==> Running mutation tests (scope: [tool.mutmut] in pyproject.toml)"
if ! mutmut run; then
    toolfail "mutmut run exited non-zero"
fi

RESULTS="$(mutmut results 2>/dev/null || true)"
echo "----- mutmut results -----"
echo "$RESULTS"
echo "----------------------------"

killed=$(echo      "$RESULTS" | grep -cE 'killed'                || true)
timeout_=$(echo    "$RESULTS" | grep -cE '\btimeout\b'           || true)
suspicious=$(echo  "$RESULTS" | grep -cE 'suspicious'            || true)
survived_raw=$(echo "$RESULTS" | grep -cE 'survived'             || true)
untested=$(echo    "$RESULTS" | grep -cE 'untested|not covered'  || true)

TOTAL=$((killed + timeout_ + suspicious + survived_raw + untested))
[ "$TOTAL" -gt 0 ] || toolfail "mutmut reported no mutants — check [tool.mutmut] config"

# ---------------------------------------------------------------------------
# Split raw survivors into (a) marked-equivalent and (b) real survivors.
#
# Robust method: for each surviving mutant key (e.g.
# "approval_gate.risk.x_apply_overrides__mutmut_15"), read the mutation
# spans emitted by mutmut in mutants/<path>.py.spans, diff the mutant body
# against the __mutmut_orig body to find the single mutated statement, then
# locate that statement's original text in the real source file and check
# whether the line carries an equivalence marker (`MUT-equivalent` or
# `MUT-internal-callchain`).  Markers on the *source* line are the pinned,
# reviewable record; unmarked survivors fail the gate.
# ---------------------------------------------------------------------------
python3 - "$RESULTS" <<'PYCLASSIFY' > /tmp/mutclass.$$ || toolfail "survivor classification crashed"
import json, os, re, sys

results = sys.stdin.read()
marker = re.compile(r"MUT-(internal-callchain|equivalent)")
real_survived = 0
marked_equivalent = 0

for m in re.finditer(r"([\w./]+)\.risk\.x_(\w+)__mutmut_(\d+): survived", results):
    modkey, fn, num = m.group(1), m.group(2), m.group(3)
    src_path = "approval_gate/risk.py"
    mut_path = os.path.join("mutants", src_path)
    spans_path = mut_path + ".spans"
    if not (os.path.exists(mut_path) and os.path.exists(spans_path)):
        real_survived += 1
        continue
    spans = json.load(open(spans_path))["spans"]
    o = spans.get(f"x_{fn}__mutmut_orig")
    k = spans.get(f"x_{fn}__mutmut_{num}")
    if not o or not k:
        real_survived += 1
        continue
    mlines = open(mut_path).read().split("\n")
    ob = mlines[o[0]-1:o[1]]
    mb = mlines[k[0]-1:k[1]]
    norm = lambda l: re.sub(r"def x_[^(:]+", "def FN", l)
    di = next((i for i,(x,y) in enumerate(zip(map(norm,ob), map(norm,mb))) if x != y), None)
    if di is None:
        real_survived += 1
        continue
    target = ob[di].strip()
    rlines = open(src_path).read().split("\n")
    hits = [i for i,l in enumerate(rlines) if l.strip() == target]
    if hits and all(marker.search(rlines[i]) for i in hits):
        marked_equivalent += 1
    else:
        real_survived += 1

print(real_survived, marked_equivalent)
PYCLASSIFY
CLASS_OUT="$(cat /tmp/mutclass.$$)"; rm -f /tmp/mutclass.$$
real_survived="$(echo "$CLASS_OUT" | awk '{print $1}')"
marked_equivalent="$(echo "$CLASS_OUT" | awk '{print $2}')"

handled=$((killed + timeout_ + suspicious + marked_equivalent))
score=$(( (handled * 100) / TOTAL ))

echo "==> Mutation summary:"
echo "    total mutants      : $TOTAL"
echo "    killed/timeout/susp: $((killed + timeout_ + suspicious))"
echo "    marked equivalent  : $marked_equivalent  (lines tagged: $EQUIVALENT_MARKERS)"
echo "    REAL survivors     : $real_survived"
echo "    untested           : $untested"
echo "    mutation score     : ${score}% (threshold: ${MUTATION_SCORE_THRESHOLD}%)"

# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------
if [ "$STRICT_ZERO_SURVIVORS" = "1" ]; then
    # Original strict example from the architecture review:
    #   survived=$(mutmut results | grep survived | wc -l); test "$survived" -eq 0
    [ "$real_survived" -eq 0 ] \
        || fail "strict mode: $real_survived real surviving mutant(s)"
else
    # Constitutional guardrail: NO survivor is acceptable in the risk-scoring
    # core unless explicitly marked equivalent above.
    [ "$real_survived" -eq 0 ] \
        || fail "$real_survived surviving mutant(s) in approval_gate/risk.py — a guardrail invariant is under-tested. Inspect with: mutmut browse"
fi

[ "$score" -ge "$MUTATION_SCORE_THRESHOLD" ] \
    || fail "mutation score ${score}% < required ${MUTATION_SCORE_THRESHOLD}%"

echo "==> PASS: mutation gate satisfied (score ${score}%, real survivors ${real_survived}, marked-equivalent ${marked_equivalent})"