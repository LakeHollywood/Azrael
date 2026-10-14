import { describe, it, expect } from 'vitest';
import { simulateEval } from './extracted/simulateEval';

describe('simulateEval — AZRAEL predicate evaluation order', () => {
  it('accepts a fully valid evaluation (all guards pass)', () => {
    const r = simulateEval(false, false, true, true);
    expect(r.code).toBe(0);
    expect(r.label).toBe('AZRAEL_OK');
    expect(r.color).toBe('text-emerald-400');
  });

  it('rejects null ctx pointer with boundary violation (-3)', () => {
    const r = simulateEval(true, false, true, true);
    expect(r.code).toBe(-3);
    expect(r.label).toBe('AZRAEL_ERR_BOUNDARY_VIOLATION');
  });

  it('rejects null payload pointer with boundary violation (-3)', () => {
    const r = simulateEval(false, true, true, true);
    expect(r.code).toBe(-3);
    expect(r.label).toBe('AZRAEL_ERR_BOUNDARY_VIOLATION');
  });

  it('rejects missing authority flag with boundary violation (-3)', () => {
    const r = simulateEval(false, false, false, true);
    expect(r.code).toBe(-3);
    expect(r.detail).toMatch(/Authority flag/);
  });

  it('rejects digest mismatch with -7 only after pointer/authority checks pass', () => {
    const r = simulateEval(false, false, true, false);
    expect(r.code).toBe(-7);
    expect(r.label).toBe('AZRAEL_ERR_DIGEST_MISMATCH');
  });

  it('null-pointer guard takes precedence over authority and digest failures', () => {
    const r = simulateEval(true, true, false, false);
    expect(r.code).toBe(-3);
    expect(r.detail).toMatch(/Null pointer/);
  });

  it('authority gate takes precedence over digest mismatch', () => {
    const r = simulateEval(false, false, false, false);
    expect(r.code).toBe(-3);
    expect(r.detail).toMatch(/Authority flag/);
  });

  it('reports deterministic latency per failure mode', () => {
    expect(simulateEval(true, false, true, true).latency).toBe('0.02ms');
    expect(simulateEval(false, false, false, true).latency).toBe('0.04ms');
    expect(simulateEval(false, false, true, false).latency).toBe('0.12ms');
    expect(simulateEval(false, false, true, true).latency).toBe('0.08ms');
  });

  it('exhaustively: code is 0 iff every guard passes', () => {
    for (const ctxNull of [false, true]) {
      for (const payloadNull of [false, true]) {
        for (const authorityFlag of [false, true]) {
          for (const digestMatch of [false, true]) {
            const ok = !ctxNull && !payloadNull && authorityFlag && digestMatch;
            const r = simulateEval(ctxNull, payloadNull, authorityFlag, digestMatch);
            expect(r.code === 0).toBe(ok);
          }
        }
      }
    }
  });
});
