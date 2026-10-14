import { describe, it, expect } from 'vitest';
import { analyzeDigestDiff } from './extracted/analyzeDigestDiff';

describe('analyzeDigestDiff', () => {
  it('reports zero mismatches for identical digests', () => {
    const r = analyzeDigestDiff('abcd1234', 'abcd1234');
    expect(r.mismatchCount).toBe(0);
    expect(r.totalLength).toBe(8);
    expect(r.diffs.every((d) => d.match)).toBe(true);
    expect(r.firstMismatch).toBe(-1);
  });

  it('detects the incident-log digests as fully divergent from offset 0', () => {
    // Values from AzraelIncidentLog's telemetry_event fixture
    const r = analyzeDigestDiff('6f61155e8c11a00a223f18e', 'bf53352d19208a00223f18f');
    expect(r.totalLength).toBe(23);
    expect(r.diffs[0]).toEqual({ index: 0, boundChar: '6', targetChar: 'b', match: false });
    expect(r.firstMismatch).toBe(0);
    expect(r.mismatchCount).toBeGreaterThan(0);
  });

  it('counts only genuinely differing positions', () => {
    const r = analyzeDigestDiff('aaaaXaaa', 'aaaaYaaa');
    expect(r.mismatchCount).toBe(1);
    expect(r.firstMismatch).toBe(4);
    expect(r.lastMismatch).toBe(4);
  });

  it('pads shorter operand with middle-dot and marks it mismatched', () => {
    const r = analyzeDigestDiff('abc', 'abcde');
    expect(r.totalLength).toBe(5);
    expect(r.diffs[3]).toEqual({ index: 3, boundChar: '·', targetChar: 'd', match: false });
    expect(r.diffs[4].boundChar).toBe('·');
    expect(r.mismatchCount).toBe(2);
    expect(r.lastMismatch).toBe(4);
  });

  it('handles two empty strings', () => {
    const r = analyzeDigestDiff('', '');
    expect(r.diffs).toHaveLength(0);
    expect(r.mismatchCount).toBe(0);
    expect(r.totalLength).toBe(0);
  });

  it('firstMismatch/lastMismatch bracket the divergence range', () => {
    const r = analyzeDigestDiff('XXhelloYY', 'ZZhelloWW');
    expect(r.firstMismatch).toBe(0);
    expect(r.lastMismatch).toBe(8);
    expect(r.mismatchCount).toBe(4);
    expect(r.diffs.slice(2, 7).every((d) => d.match)).toBe(true);
  });

  it('diffs array is indexed contiguously from 0 to totalLength-1', () => {
    const r = analyzeDigestDiff('0123456789abcdef', '0123456789abcdee');
    expect(r.diffs.map((d) => d.index)).toEqual([...Array(16).keys()]);
    expect(r.mismatchCount).toBe(1);
    expect(r.firstMismatch).toBe(15);
  });
});
