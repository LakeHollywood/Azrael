/**
 * TS -> Python parity test for the risk-score-to-policy mapping.
 *
 * Pins the constitutional invariant shared by src/lib/approvalGates.ts and
 * approval_gate/risk.py: for every score 0..100 (plus clamp cases), the TS
 * `policyValueForScore` must equal Python `determine_policy(score).value`.
 * Explicitly pins 70 -> 'dual_approval' / DUAL_APPROVAL (the refund gate).
 */
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import {
  AUTHZ_RISK_FLOOR,
  GATE_MODIFICATION_RISK_FLOOR,
  POLICY_THRESHOLDS,
  RISK_SCORE_MAX,
  RISK_SCORE_MIN,
  clampScore,
  policyForScore,
  policyValueForScore,
} from '@/lib/approvalGates';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');

/** Run the real Python engine once for a batch of scores; returns score->policy map. */
function pythonPolicies(scores: number[]): Record<string, string> {
  const script = `
import json, sys
sys.path.insert(0, ${JSON.stringify(REPO_ROOT)})
from approval_gate.risk import determine_policy
scores = json.loads(sys.argv[1])
print(json.dumps({str(s): determine_policy(s).value for s in scores}))
`;
  const out = execFileSync('python3', ['-c', script, JSON.stringify(scores)], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  });
  return JSON.parse(out);
}

const ALL_SCORES = Array.from(
  { length: RISK_SCORE_MAX - RISK_SCORE_MIN + 1 },
  (_, i) => i
);

describe('TS/Python risk-policy parity (approval_gate/risk.py <-> approvalGates.ts)', () => {
  it('matches determine_policy for every integer score 0..100', () => {
    const py = pythonPolicies(ALL_SCORES);
    const mismatches = ALL_SCORES.filter(
      (s) => py[String(s)] !== policyValueForScore(s)
    );
    expect(mismatches).toEqual([]);
  });

  it('matches on fractional and out-of-range (clamped) scores', () => {
    const edge = [-10, -0.5, 0, 19.5, 20, 59.9, 60, 70.4, 79.9, 80, 100, 100.5, 250];
    const py = pythonPolicies(edge);
    for (const s of edge) {
      expect(policyValueForScore(s), `score ${s}`).toBe(py[String(s)]);
    }
  });

  it('mirrors clamp_score', () => {
    const edge = [-100, -1, 0, 50, 100, 101, 9999];
    const script = `
import json, sys
sys.path.insert(0, ${JSON.stringify(REPO_ROOT)})
from approval_gate.risk import clamp_score
print(json.dumps([clamp_score(s) for s in json.loads(sys.argv[1])]))
`;
    const py: number[] = JSON.parse(
      execFileSync('python3', ['-c', script, JSON.stringify(edge)], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
      })
    );
    edge.forEach((s, i) => expect(clampScore(s)).toBe(py[i]));
  });

  it('pins band tables identical to Python POLICY_THRESHOLDS', () => {
    const script = `
import json, sys
sys.path.insert(0, ${JSON.stringify(REPO_ROOT)})
from approval_gate.risk import POLICY_THRESHOLDS as P
print(json.dumps([[lb, pol.value] for lb, pol in P]))
`;
    const py: [number, string][] = JSON.parse(
      execFileSync('python3', ['-c', script], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
      })
    );
    expect(POLICY_THRESHOLDS.map((b) => [b.lowerBound, b.value])).toEqual(py);
    expect(AUTHZ_RISK_FLOOR).toBe(60);
    expect(GATE_MODIFICATION_RISK_FLOOR).toBe(100);
  });
});

describe('refund gate pin: score 70 -> DUAL_APPROVAL', () => {
  // The exact component sum from src/actions/financial/refund.ts:
  // 25 + 20 + 15 + 0 + 5 + 5 + 0 = 70
  it('maps 70 to DUAL_APPROVAL in TS', () => {
    expect(policyForScore(70)).toBe('DUAL_APPROVAL');
    expect(policyValueForScore(70)).toBe('dual_approval');
  });

  it('maps 70 to dual_approval in the Python engine', () => {
    expect(pythonPolicies([70])['70']).toBe('dual_approval');
  });

  it('agrees with create_approval_record metadata', () => {
    const script = `
import json, sys
sys.path.insert(0, ${JSON.stringify(REPO_ROOT)})
from approval_gate.risk import create_approval_record
r = create_approval_record(70, operation="financial.issue_stripe_refund")
print(json.dumps({"risk_score": r["risk_score"], "approval_policy": r["approval_policy"]}))
`;
    const rec = JSON.parse(
      execFileSync('python3', ['-c', script], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
      })
    );
    expect(rec.approval_policy).toBe(policyValueForScore(70));
    expect(rec.risk_score).toBe(70);
  });
});
