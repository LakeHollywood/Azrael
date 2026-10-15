// Test-support module: logic copied verbatim from src/components/AzraelIncidentLog.tsx
// (analyzeDigestDiff). Keep in sync with the component source.

function analyzeDigestDiff(bound: string, target: string) {
  const maxLen = Math.max(bound.length, target.length);
  const diffs: { index: number; boundChar: string; targetChar: string; match: boolean }[] = [];

  for (let i = 0; i < maxLen; i++) {
    const bc = bound[i] || '·';
    const tc = target[i] || '·';
    diffs.push({ index: i, boundChar: bc, targetChar: tc, match: bc === tc });
  }

  const mismatchCount = diffs.filter((d) => !d.match).length;
  const firstMismatch = diffs.findIndex((d) => !d.match);
  const lastMismatch = diffs.length - 1 - [...diffs].reverse().findIndex((d) => !d.match);

  return { diffs, mismatchCount, firstMismatch, lastMismatch, totalLength: maxLen };
}

export { analyzeDigestDiff };
