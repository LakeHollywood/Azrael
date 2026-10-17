// Test-support module: logic copied verbatim from src/components/AzraelEngine.tsx
// (simulateEval + EvalResult). Keep in sync with the component source.

interface EvalResult {
  code: number;
  label: string;
  color: string;
  detail: string;
  latency: string;
}

function simulateEval(
  ctxNull: boolean,
  payloadNull: boolean,
  authorityFlag: boolean,
  digestMatch: boolean,
): EvalResult {
  if (ctxNull || payloadNull) {
    return {
      code: -3,
      label: 'AZRAEL_ERR_BOUNDARY_VIOLATION',
      color: 'text-red-400',
      detail: 'Null pointer detected. Predicate evaluation aborted before entering safety-critical path.',
      latency: '0.02ms',
    };
  }
  if (!authorityFlag) {
    return {
      code: -3,
      label: 'AZRAEL_ERR_BOUNDARY_VIOLATION',
      color: 'text-red-400',
      detail: 'Authority flag bit 0 not set. Containment protocol activated — thread state revoked.',
      latency: '0.04ms',
    };
  }
  if (!digestMatch) {
    return {
      code: -7,
      label: 'AZRAEL_ERR_DIGEST_MISMATCH',
      color: 'text-orange-400',
      detail: 'Constant-time comparison detected mismatch. Payload integrity cannot be verified.',
      latency: '0.12ms',
    };
  }
  return {
    code: 0,
    label: 'AZRAEL_OK',
    color: 'text-emerald-400',
    detail: 'All predicates satisfied. Authority verified, digest matches, payload accepted.',
    latency: '0.08ms',
  };
}

export { simulateEval };
export type { EvalResult };
