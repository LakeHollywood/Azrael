import { useState, useEffect } from 'react';

// ── Incident Data ───────────────────────────────────────────────────
const incident = {
  system_layer: 'AZRAEL_RUNTIME',
  status_code: -1,
  status_label: 'AZRAEL_ERR_DIGEST_MISMATCH',
  sts_sequence_id: 10492834,
  telemetry_event: {
    bound_digest: '6f61155e8c11a00a223f18e',
    target_digest: 'bf53352d19208a00223f18f',
    authority_flags: '0x00000001',
    thread_revoked: true,
  },
  ratification_status: 'REJECTED_UNRATIFIED_HEADER',
  ledger_record_state: 'PASS_PUBLISHED_V1_1',
};

// ── Digest Diff Analyzer ────────────────────────────────────────────
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

// ── Timeline Event ──────────────────────────────────────────────────
interface TimelineStep {
  time: string;
  label: string;
  detail: string;
  status: 'ok' | 'warn' | 'fail';
  icon: string;
}

const timelineSteps: TimelineStep[] = [
  {
    time: 'T+0.000ms',
    label: 'Predicate invocation received',
    detail: 'azrael_eval_predicate() called with sequence_id=10492834',
    status: 'ok',
    icon: 'fa-arrow-right-to-bracket',
  },
  {
    time: 'T+0.003ms',
    label: 'Null pointer guard — PASSED',
    detail: 'ctx != NULL, payload_ptr != NULL',
    status: 'ok',
    icon: 'fa-check',
  },
  {
    time: 'T+0.007ms',
    label: 'Authority flag check — PASSED',
    detail: 'authority_flags & 0x01 == 1 (0x00000001)',
    status: 'ok',
    icon: 'fa-lock-open',
  },
  {
    time: 'T+0.011ms',
    label: 'Digest verification — FAILED',
    detail: 'Constant-time comparison detected mismatch at byte offset 0',
    status: 'fail',
    icon: 'fa-xmark',
  },
  {
    time: 'T+0.012ms',
    label: 'Thread state revocation initiated',
    detail: '[AZRAEL CONTAINMENT] Revoking thread state. Code: -1',
    status: 'fail',
    icon: 'fa-skull',
  },
  {
    time: 'T+0.014ms',
    label: 'Ledger record published',
    detail: 'PASS_PUBLISHED_V1_1 — immutable audit entry written',
    status: 'warn',
    icon: 'fa-book',
  },
];

// ── Hex Block Component ─────────────────────────────────────────────
function HexBlock({ label, hex, highlightIndices, color }: {
  label: string;
  hex: string;
  highlightIndices: number[];
  color: 'red' | 'cyan';
}) {
  const colorClasses = {
    red: 'bg-red-500/30 text-red-300 border-red-500/50',
    cyan: 'bg-cyan-500/30 text-cyan-300 border-cyan-500/50',
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-500 font-semibold uppercase tracking-wider">{label}</span>
        <span className="text-xs text-slate-600 font-mono">{hex.length} chars</span>
      </div>
      <div className="bg-slate-950/80 rounded-lg p-3 border border-slate-800 font-mono text-sm overflow-x-auto">
        <div className="flex flex-wrap gap-0">
          {hex.split('').map((char, i) => (
            <span
              key={i}
              className={`inline-block w-5 text-center transition-all duration-200 ${
                highlightIndices.includes(i)
                  ? `${colorClasses[color]} rounded-sm border font-bold`
                  : 'text-slate-500'
              }`}
              title={highlightIndices.includes(i) ? `Offset 0x${i.toString(16).padStart(2, '0')} — MISMATCH` : undefined}
            >
              {char}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Main Component ──────────────────────────────────────────────────
export default function AzraelIncidentLog() {
  const [showTimeline, setShowTimeline] = useState(false);
  const [activeStep, setActiveStep] = useState<number | null>(null);
  const [hexView, setHexView] = useState<'inline' | 'column'>('inline');

  useEffect(() => {
    const timer = setTimeout(() => setShowTimeline(true), 300);
    return () => clearTimeout(timer);
  }, []);

  const { diffs, mismatchCount, firstMismatch, lastMismatch } = analyzeDigestDiff(
    incident.telemetry_event.bound_digest,
    incident.telemetry_event.target_digest,
  );

  const mismatchIndices = diffs.filter((d) => !d.match).map((d) => d.index);

  return (
    <section id="incident" className="py-24 px-6 bg-gradient-to-b from-slate-950 via-red-950/5 to-slate-950">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="text-center mb-16">
          <div className="inline-flex items-center gap-2 bg-red-500/10 border border-red-500/30 rounded-full px-4 py-2 mb-6">
            <span className="w-2 h-2 bg-red-400 rounded-full animate-pulse"></span>
            <span className="text-sm text-red-300 font-medium">RUNTIME INCIDENT — SEQUENCE #{incident.sts_sequence_id}</span>
          </div>
          <h2 className="text-4xl font-bold mt-3 mb-4">
            <span className="bg-gradient-to-r from-red-400 via-red-300 to-orange-300 bg-clip-text text-transparent">
              Digest Mismatch Event
            </span>
          </h2>
          <p className="text-slate-400 max-w-2xl mx-auto">
            Forensic reconstruction of Azrael runtime containment event. Thread revoked at T+0.012ms 
            after constant-time digest comparison detected payload tampering.
          </p>
        </div>

        {/* Status Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-10">
          <div className="bg-slate-900/60 border border-red-500/20 rounded-xl p-5">
            <div className="text-xs text-slate-500 mb-1">Status Code</div>
            <div className="text-2xl font-bold font-mono text-red-400">{incident.status_code}</div>
            <div className="text-xs text-red-400/70 mt-1 font-mono">{incident.status_label}</div>
          </div>
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
            <div className="text-xs text-slate-500 mb-1">Sequence ID</div>
            <div className="text-2xl font-bold font-mono text-white">{incident.sts_sequence_id.toLocaleString()}</div>
            <div className="text-xs text-slate-500 mt-1">Monotonic counter</div>
          </div>
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
            <div className="text-xs text-slate-500 mb-1">Thread Revoked</div>
            <div className="text-2xl font-bold text-red-400 flex items-center gap-2">
              <i className="fa-solid fa-skull-crossbones"></i>
              YES
            </div>
            <div className="text-xs text-slate-500 mt-1">Containment active</div>
          </div>
          <div className="bg-slate-900/60 border border-orange-500/20 rounded-xl p-5">
            <div className="text-xs text-slate-500 mb-1">Ratification</div>
            <div className="text-lg font-bold text-orange-400">REJECTED</div>
            <div className="text-xs text-orange-400/70 mt-1 font-mono">UNRATIFIED_HEADER</div>
          </div>
        </div>

        {/* Digest Comparison */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden mb-10">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-red-500/20 flex items-center justify-center">
                <i className="fa-solid fa-fingerprint text-red-400 text-sm"></i>
              </div>
              <div>
                <h3 className="font-bold text-slate-200">Digest Forensic Comparison</h3>
                <p className="text-xs text-slate-500">{mismatchCount} byte{mismatchCount !== 1 ? 's' : ''} differ — first divergence at offset 0x{firstMismatch.toString(16).padStart(2, '0')}</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setHexView('inline')}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  hexView === 'inline' ? 'bg-slate-700 text-white' : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                Inline
              </button>
              <button
                onClick={() => setHexView('column')}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  hexView === 'column' ? 'bg-slate-700 text-white' : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                Column
              </button>
            </div>
          </div>

          <div className="p-6">
            {hexView === 'inline' ? (
              <div className="space-y-6">
                <HexBlock
                  label="Bound Digest (Expected)"
                  hex={incident.telemetry_event.bound_digest}
                  highlightIndices={mismatchIndices}
                  color="cyan"
                />
                <HexBlock
                  label="Target Digest (Received)"
                  hex={incident.telemetry_event.target_digest}
                  highlightIndices={mismatchIndices}
                  color="red"
                />
                {/* Diff summary bar */}
                <div className="bg-slate-950/60 rounded-lg p-3 border border-slate-800">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-xs text-slate-500">Diff map:</span>
                    <span className="text-xs text-slate-600 font-mono">
                      [{firstMismatch}..{lastMismatch}] — {mismatchCount} mismatches in {diffs.length} chars
                    </span>
                  </div>
                  <div className="flex h-3 rounded-full overflow-hidden">
                    {diffs.map((d, i) => (
                      <div
                        key={i}
                        className={`flex-1 ${d.match ? 'bg-emerald-500/40' : 'bg-red-500/80'}`}
                        title={d.match ? `Match at 0x${i.toString(16)}` : `Mismatch at 0x${i.toString(16)}`}
                      />
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="bg-slate-950/80 rounded-lg p-4 border border-slate-800 font-mono text-sm">
                <div className="grid grid-cols-[auto_1fr_1fr_auto] gap-x-4 gap-y-0.5">
                  <span className="text-slate-600 text-xs">OFFSET</span>
                  <span className="text-cyan-400/60 text-xs">BOUND</span>
                  <span className="text-red-400/60 text-xs">TARGET</span>
                  <span className="text-slate-600 text-xs">STATUS</span>
                  {diffs.map((d) => (
                    <>
                      <span key={`o-${d.index}`} className="text-slate-600 text-xs">
                        0x{d.index.toString(16).padStart(2, '0')}
                      </span>
                      <span key={`b-${d.index}`} className={d.match ? 'text-slate-400' : 'text-cyan-300 font-bold'}>
                        {d.boundChar}
                      </span>
                      <span key={`t-${d.index}`} className={d.match ? 'text-slate-400' : 'text-red-300 font-bold'}>
                        {d.targetChar}
                      </span>
                      <span key={`s-${d.index}`} className={`text-xs ${d.match ? 'text-emerald-500' : 'text-red-400'}`}>
                        {d.match ? '✓' : '✗'}
                      </span>
                    </>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Execution Timeline */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden mb-10">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-orange-500/20 flex items-center justify-center">
              <i className="fa-solid fa-timeline text-orange-400 text-sm"></i>
            </div>
            <div>
              <h3 className="font-bold text-slate-200">Execution Timeline</h3>
              <p className="text-xs text-slate-500">Full trace from invocation to containment — 0.014ms total</p>
            </div>
          </div>

          <div className="p-6">
            <div className="relative">
              {/* Vertical line */}
              <div className="absolute left-5 top-0 bottom-0 w-px bg-slate-800"></div>

              <div className="space-y-1">
                {timelineSteps.map((step, i) => {
                  const statusColors = {
                    ok: { bg: 'bg-emerald-500/20', border: 'border-emerald-500/30', text: 'text-emerald-400', icon: 'text-emerald-400' },
                    warn: { bg: 'bg-orange-500/20', border: 'border-orange-500/30', text: 'text-orange-400', icon: 'text-orange-400' },
                    fail: { bg: 'bg-red-500/20', border: 'border-red-500/30', text: 'text-red-400', icon: 'text-red-400' },
                  };
                  const colors = statusColors[step.status];

                  return (
                    <div
                      key={i}
                      onMouseEnter={() => setActiveStep(i)}
                      onMouseLeave={() => setActiveStep(null)}
                      className={`relative flex items-start gap-4 pl-12 pr-4 py-3 rounded-xl transition-all cursor-pointer ${
                        activeStep === i ? 'bg-slate-800/40' : ''
                      } ${showTimeline ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-4'}`}
                      style={{ transitionDelay: `${i * 100}ms` }}
                    >
                      {/* Node */}
                      <div className={`absolute left-2.5 w-5 h-5 rounded-full ${colors.bg} border ${colors.border} flex items-center justify-center z-10`}>
                        <i className={`fa-solid ${step.icon} text-[8px] ${colors.icon}`}></i>
                      </div>

                      {/* Content */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-3 mb-1">
                          <span className="text-xs text-slate-600 font-mono w-20 shrink-0">{step.time}</span>
                          <span className={`text-sm font-medium ${colors.text}`}>{step.label}</span>
                        </div>
                        <p className="text-xs text-slate-500 ml-[5.25rem]">{step.detail}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* Ledger & Authority State */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Authority Flags */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
            <h3 className="font-bold text-slate-200 mb-4 flex items-center gap-2">
              <i className="fa-solid fa-flag text-cyan-400"></i>
              Authority Flags Register
            </h3>
            <div className="bg-slate-950/80 rounded-lg p-4 border border-slate-800 mb-4">
              <div className="font-mono text-lg text-cyan-300 tracking-widest text-center">
                {incident.telemetry_event.authority_flags}
              </div>
            </div>
            <div className="space-y-2">
              {[
                { bit: 0, name: 'BOUNDARY_AUTH', desc: 'Predicate evaluation authorized', active: true },
                { bit: 1, name: 'CRYPTO_SEAL', desc: 'Cryptographic seal verification', active: false },
                { bit: 2, name: 'AUDIT_TRAIL', desc: 'Immutable audit logging', active: false },
                { bit: 3, name: 'REMOTE_ATTEST', desc: 'Remote attestation required', active: false },
              ].map((flag) => (
                <div key={flag.bit} className="flex items-center gap-3">
                  <span className={`w-6 h-6 rounded flex items-center justify-center text-xs font-mono font-bold ${
                    flag.active ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-slate-800 text-slate-600 border border-slate-700'
                  }`}>
                    {flag.active ? '1' : '0'}
                  </span>
                  <span className="text-sm font-mono text-slate-300">{flag.name}</span>
                  <span className="text-xs text-slate-600 ml-auto">{flag.desc}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Ledger State */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
            <h3 className="font-bold text-slate-200 mb-4 flex items-center gap-2">
              <i className="fa-solid fa-book text-indigo-400"></i>
              Ledger Record State
            </h3>
            <div className="bg-gradient-to-r from-indigo-500/5 to-purple-500/5 border border-indigo-500/20 rounded-xl p-5 mb-4">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-10 h-10 rounded-lg bg-indigo-500/20 flex items-center justify-center">
                  <i className="fa-solid fa-stamp text-indigo-400"></i>
                </div>
                <div>
                  <div className="font-mono text-sm text-indigo-300 font-bold">{incident.ledger_record_state}</div>
                  <div className="text-xs text-slate-500">Immutable audit entry</div>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="bg-slate-900/60 rounded-lg p-2">
                  <span className="text-slate-500">Record Type</span>
                  <div className="text-slate-300 font-medium mt-0.5">PASS_PUBLISHED</div>
                </div>
                <div className="bg-slate-900/60 rounded-lg p-2">
                  <span className="text-slate-500">Version</span>
                  <div className="text-slate-300 font-medium mt-0.5">V1.1</div>
                </div>
                <div className="bg-slate-900/60 rounded-lg p-2">
                  <span className="text-slate-500">Chain Position</span>
                  <div className="text-slate-300 font-medium mt-0.5 font-mono">#10,492,834</div>
                </div>
                <div className="bg-slate-900/60 rounded-lg p-2">
                  <span className="text-slate-500">Finality</span>
                  <div className="text-emerald-400 font-medium mt-0.5">FINAL</div>
                </div>
              </div>
            </div>
            <div className="text-xs text-slate-500 flex items-center gap-2">
              <i className="fa-solid fa-shield-halved text-indigo-400/50"></i>
              Record is cryptographically sealed and cannot be modified or deleted
            </div>
          </div>
        </div>

        {/* Raw JSON */}
        <div className="mt-10 bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
          <details className="group">
            <summary className="px-6 py-4 cursor-pointer flex items-center justify-between hover:bg-slate-800/30 transition-colors">
              <div className="flex items-center gap-3">
                <i className="fa-solid fa-code text-slate-500"></i>
                <span className="text-sm text-slate-400 font-medium">Raw Incident JSON</span>
              </div>
              <i className="fa-solid fa-chevron-down text-slate-600 text-xs group-open:rotate-180 transition-transform"></i>
            </summary>
            <div className="px-6 pb-6">
              <pre className="bg-slate-950/80 rounded-lg p-4 border border-slate-800 text-xs font-mono text-slate-400 overflow-x-auto">
                {JSON.stringify(incident, null, 2)}
              </pre>
            </div>
          </details>
        </div>
      </div>
    </section>
  );
}
