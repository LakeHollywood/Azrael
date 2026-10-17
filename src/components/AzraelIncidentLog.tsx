import { useState, useEffect, useRef } from 'react';

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

// ── Hex Dump Formatter ──────────────────────────────────────────────
function toHexDump(hex: string, bytesPerRow = 8) {
  const rows: { offset: string; bytes: string[]; ascii: string }[] = [];
  for (let i = 0; i < hex.length; i += bytesPerRow * 2) {
    const chunk = hex.slice(i, i + bytesPerRow * 2);
    const bytes: string[] = [];
    let ascii = '';
    for (let j = 0; j < chunk.length; j += 2) {
      const byte = chunk.slice(j, j + 2);
      bytes.push(byte);
      const code = parseInt(byte, 16);
      ascii += code >= 32 && code <= 126 ? String.fromCharCode(code) : '.';
    }
    rows.push({
      offset: (i / 2).toString(16).toUpperCase().padStart(8, '0'),
      bytes,
      ascii,
    });
  }
  return rows;
}

// ── Byte-level Diff ─────────────────────────────────────────────────
interface ByteDiff {
  offset: number;
  boundByte: string;
  targetByte: string;
  match: boolean;
}

function computeByteDiff(bound: string, target: string): ByteDiff[] {
  const maxLen = Math.max(bound.length, target.length);
  const diffs: ByteDiff[] = [];
  for (let i = 0; i < maxLen; i += 2) {
    const bb = bound.slice(i, i + 2) || '??';
    const tb = target.slice(i, i + 2) || '??';
    diffs.push({ offset: i / 2, boundByte: bb, targetByte: tb, match: bb === tb });
  }
  return diffs;
}

// ── Containment Replay ──────────────────────────────────────────────
interface ReplayFrame {
  time: string;
  elapsed: string;
  label: string;
  detail: string;
  status: 'ok' | 'warn' | 'fail' | 'critical';
  icon: string;
  sourceRef?: string;
}

const replayFrames: ReplayFrame[] = [
  {
    time: 'T+0.000ms',
    elapsed: '0%',
    label: 'azrael_eval_predicate() invoked',
    detail: 'ctx=0x7f3a..., payload_ptr=0x7f3a..., payload_len=29',
    status: 'ok',
    icon: 'fa-arrow-right-to-bracket',
    sourceRef: 'azrael_engine.rs:38',
  },
  {
    time: 'T+0.002ms',
    elapsed: '14%',
    label: 'catch_unwind scope entered',
    detail: 'Panic containment active — all unwinds caught',
    status: 'ok',
    icon: 'fa-shield-halved',
    sourceRef: 'azrael_engine.rs:41',
  },
  {
    time: 'T+0.004ms',
    elapsed: '28%',
    label: 'Null pointer guard — PASSED',
    detail: 'ctx != NULL ✓, payload_ptr != NULL ✓',
    status: 'ok',
    icon: 'fa-check',
    sourceRef: 'azrael_engine.rs:42-44',
  },
  {
    time: 'T+0.006ms',
    elapsed: '42%',
    label: 'slice::from_raw_parts() — payload bound',
    detail: 'payload = &[u8](29 bytes) — zero-copy FFI slice',
    status: 'ok',
    icon: 'fa-link',
    sourceRef: 'azrael_engine.rs:47',
  },
  {
    time: 'T+0.008ms',
    elapsed: '57%',
    label: 'validate_predicate() — authority check',
    detail: 'authority_flags & 0x01 == 1 (0x00000001) — PASSED',
    status: 'ok',
    icon: 'fa-lock-open',
    sourceRef: 'azrael_engine.rs:26-29',
  },
  {
    time: 'T+0.010ms',
    elapsed: '71%',
    label: 'verify_digest() — constant-time comparison',
    detail: 'subtle::ConstantTimeEq::ct_eq() executing...',
    status: 'warn',
    icon: 'fa-fingerprint',
    sourceRef: 'azrael_engine.rs:21-22',
  },
  {
    time: 'T+0.012ms',
    elapsed: '85%',
    label: 'DIGEST MISMATCH DETECTED',
    detail: 'bound≠target at byte offset 0x00 — 7 bytes diverge',
    status: 'critical',
    icon: 'fa-xmark',
    sourceRef: 'azrael_engine.rs:22',
  },
  {
    time: 'T+0.013ms',
    elapsed: '92%',
    label: '[AZRAEL CONTAINMENT] Thread state revoked',
    detail: 'eprintln!("[AZRAEL CONTAINMENT] Revoking thread state. Code: -1")',
    status: 'critical',
    icon: 'fa-skull',
    sourceRef: 'azrael_engine.rs:51-53',
  },
  {
    time: 'T+0.014ms',
    elapsed: '100%',
    label: 'Ledger record sealed — PASS_PUBLISHED_V1_1',
    detail: 'Immutable audit entry written at chain position #10,492,834',
    status: 'fail',
    icon: 'fa-book',
  },
];

// ── Risk Correlation ────────────────────────────────────────────────
const riskCorrelations = [
  {
    metric: 'FAA Compliance',
    impact: 'CRITICAL',
    detail: 'Digest mismatch in flight-critical telemetry violates Part 107 data integrity requirements',
    score: 23,
    color: 'red',
  },
  {
    metric: 'Data Sovereignty',
    impact: 'HIGH',
    detail: 'Unratified header suggests potential payload injection from unauthorized source',
    score: 41,
    color: 'orange',
  },
  {
    metric: 'Model Hallucination',
    impact: 'MEDIUM',
    detail: 'If digest originates from LLM output, indicates model generated non-deterministic payload',
    score: 58,
    color: 'yellow',
  },
  {
    metric: 'Operational Uptime',
    impact: 'LOW',
    detail: 'Containment successful — systemd will restart daemon within 5s (RestartSec=5s)',
    score: 89,
    color: 'emerald',
  },
];

// ── HexDumpTable Component ──────────────────────────────────────────
function HexDumpViewer() {
  const [viewMode, setViewMode] = useState<'side-by-side' | 'diff'>('side-by-side');
  const boundDump = toHexDump(incident.telemetry_event.bound_digest);
  const targetDump = toHexDump(incident.telemetry_event.target_digest);
  const byteDiffs = computeByteDiff(
    incident.telemetry_event.bound_digest,
    incident.telemetry_event.target_digest,
  );
  const mismatchOffsets = new Set(byteDiffs.filter((d) => !d.match).map((d) => d.offset));

  return (
    <div className="bg-slate-950/80 border border-slate-800 rounded-xl overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between bg-slate-900/40">
        <div className="flex items-center gap-2">
          <i className="fa-solid fa-memory text-red-400/60 text-xs"></i>
          <span className="text-xs text-slate-400 font-mono">HEX DUMP VIEWER</span>
        </div>
        <div className="flex items-center gap-1 bg-slate-800 rounded-lg p-0.5">
          <button
            onClick={() => setViewMode('side-by-side')}
            className={`px-2.5 py-1 rounded-md text-xs font-medium transition-all ${
              viewMode === 'side-by-side' ? 'bg-slate-700 text-white' : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            Side-by-Side
          </button>
          <button
            onClick={() => setViewMode('diff')}
            className={`px-2.5 py-1 rounded-md text-xs font-medium transition-all ${
              viewMode === 'diff' ? 'bg-slate-700 text-white' : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            Byte Diff
          </button>
        </div>
      </div>

      {viewMode === 'side-by-side' ? (
        <div className="grid grid-cols-2 divide-x divide-slate-800">
          {/* Bound Digest */}
          <div className="p-3">
            <div className="text-xs text-cyan-400/60 font-semibold mb-2 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
              BOUND DIGEST (Expected)
            </div>
            <table className="w-full font-mono text-xs">
              <thead>
                <tr className="text-slate-600">
                  <th className="text-left pb-1 w-16">OFFSET</th>
                  <th className="text-left pb-1">BYTES</th>
                </tr>
              </thead>
              <tbody>
                {boundDump.map((row) => (
                  <tr key={row.offset} className="hover:bg-slate-800/30">
                    <td className="text-slate-600 py-0.5">{row.offset}</td>
                    <td className="py-0.5">
                      {row.bytes.map((byte, i) => {
                        const byteOffset = parseInt(row.offset, 16) + i;
                        const isMismatch = mismatchOffsets.has(byteOffset);
                        return (
                          <span
                            key={i}
                            className={`inline-block w-6 text-center ${
                              isMismatch
                                ? 'bg-cyan-500/30 text-cyan-200 rounded font-bold'
                                : 'text-slate-400'
                            }`}
                          >
                            {byte}
                          </span>
                        );
                      })}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Target Digest */}
          <div className="p-3">
            <div className="text-xs text-red-400/60 font-semibold mb-2 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-red-400"></span>
              TARGET DIGEST (Received)
            </div>
            <table className="w-full font-mono text-xs">
              <thead>
                <tr className="text-slate-600">
                  <th className="text-left pb-1 w-16">OFFSET</th>
                  <th className="text-left pb-1">BYTES</th>
                </tr>
              </thead>
              <tbody>
                {targetDump.map((row) => (
                  <tr key={row.offset} className="hover:bg-slate-800/30">
                    <td className="text-slate-600 py-0.5">{row.offset}</td>
                    <td className="py-0.5">
                      {row.bytes.map((byte, i) => {
                        const byteOffset = parseInt(row.offset, 16) + i;
                        const isMismatch = mismatchOffsets.has(byteOffset);
                        return (
                          <span
                            key={i}
                            className={`inline-block w-6 text-center ${
                              isMismatch
                                ? 'bg-red-500/30 text-red-200 rounded font-bold'
                                : 'text-slate-400'
                            }`}
                          >
                            {byte}
                          </span>
                        );
                      })}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        /* Byte Diff View */
        <div className="p-3">
          <table className="w-full font-mono text-xs">
            <thead>
              <tr className="text-slate-600 border-b border-slate-800">
                <th className="text-left pb-2 w-16">OFFSET</th>
                <th className="text-left pb-2 w-16">BOUND</th>
                <th className="text-left pb-2 w-16">TARGET</th>
                <th className="text-left pb-2">STATUS</th>
              </tr>
            </thead>
            <tbody>
              {byteDiffs.map((d) => (
                <tr
                  key={d.offset}
                  className={`border-b border-slate-800/30 ${
                    !d.match ? 'bg-red-500/5' : ''
                  } hover:bg-slate-800/20`}
                >
                  <td className="text-slate-600 py-1">
                    0x{d.offset.toString(16).toUpperCase().padStart(2, '0')}
                  </td>
                  <td className={`py-1 ${d.match ? 'text-slate-400' : 'text-cyan-300 font-bold'}`}>
                    {d.boundByte}
                  </td>
                  <td className={`py-1 ${d.match ? 'text-slate-400' : 'text-red-300 font-bold'}`}>
                    {d.targetByte}
                  </td>
                  <td className="py-1">
                    {d.match ? (
                      <span className="text-emerald-500">✓ MATCH</span>
                    ) : (
                      <span className="text-red-400">✗ DIVERGED</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Summary bar */}
      <div className="px-4 py-2 border-t border-slate-800 bg-slate-900/40 flex items-center justify-between text-xs">
        <span className="text-slate-500">
          {byteDiffs.filter((d) => d.match).length} matched / {byteDiffs.filter((d) => !d.match).length} diverged / {byteDiffs.length} total bytes
        </span>
        <span className="text-red-400 font-mono">
          First divergence: 0x{byteDiffs.find((d) => !d.match)?.offset.toString(16).toUpperCase().padStart(2, '0') ?? 'N/A'}
        </span>
      </div>
    </div>
  );
}

// ── Containment Replay Component ────────────────────────────────────
function ContainmentReplay() {
  const [playing, setPlaying] = useState(false);
  const [currentFrame, setCurrentFrame] = useState(-1);
  const [completed, setCompleted] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const startReplay = () => {
    setPlaying(true);
    setCompleted(false);
    setCurrentFrame(0);
    let frame = 0;
    intervalRef.current = setInterval(() => {
      frame++;
      if (frame >= replayFrames.length) {
        if (intervalRef.current) clearInterval(intervalRef.current);
        setPlaying(false);
        setCompleted(true);
      } else {
        setCurrentFrame(frame);
      }
    }, 600);
  };

  const resetReplay = () => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    setPlaying(false);
    setCurrentFrame(-1);
    setCompleted(false);
  };

  useEffect(() => {
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []);

  const statusColors: Record<string, { bg: string; text: string; border: string }> = {
    ok: { bg: 'bg-emerald-500/20', text: 'text-emerald-400', border: 'border-emerald-500/30' },
    warn: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/30' },
    fail: { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/30' },
    critical: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30' },
  };

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
      <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-red-500/20 flex items-center justify-center">
            <i className="fa-solid fa-film text-red-400 text-sm"></i>
          </div>
          <div>
            <h3 className="font-bold text-slate-200">Containment Replay</h3>
            <p className="text-xs text-slate-500">Animated execution trace with source code references</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {completed && (
            <button
              onClick={resetReplay}
              className="px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-400 hover:text-white transition-all"
            >
              <i className="fa-solid fa-rotate-left mr-1"></i>
              Reset
            </button>
          )}
          <button
            onClick={playing ? resetReplay : startReplay}
            disabled={playing}
            className={`px-4 py-1.5 rounded-lg text-xs font-medium transition-all ${
              playing
                ? 'bg-red-500/20 border border-red-500/30 text-red-300'
                : 'bg-red-500/20 border border-red-500/30 text-red-300 hover:bg-red-500/30'
            }`}
          >
            {playing ? (
              <>
                <i className="fa-solid fa-spinner fa-spin mr-1"></i>
                Playing...
              </>
            ) : completed ? (
              <>
                <i className="fa-solid fa-rotate-right mr-1"></i>
                Replay
              </>
            ) : (
              <>
                <i className="fa-solid fa-play mr-1"></i>
                Start Replay
              </>
            )}
          </button>
        </div>
      </div>

      {/* Progress bar */}
      <div className="px-6 pt-3">
        <div className="w-full h-1 bg-slate-800 rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-emerald-500 via-yellow-500 to-red-500 rounded-full transition-all duration-500"
            style={{
              width: currentFrame < 0 ? '0%' : `${((currentFrame + 1) / replayFrames.length) * 100}%`,
            }}
          ></div>
        </div>
        <div className="flex justify-between mt-1 text-xs text-slate-600">
          <span>T+0.000ms</span>
          <span>Frame {Math.max(0, currentFrame + 1)} / {replayFrames.length}</span>
          <span>T+0.014ms</span>
        </div>
      </div>

      {/* Timeline */}
      <div className="p-6 max-h-[500px] overflow-y-auto">
        <div className="relative">
          <div className="absolute left-5 top-0 bottom-0 w-px bg-slate-800"></div>

          {replayFrames.map((frame, i) => {
            const isVisible = i <= currentFrame;
            const isCurrent = i === currentFrame;
            const colors = statusColors[frame.status];

            return (
              <div
                key={i}
                className={`relative flex items-start gap-4 pl-12 pr-4 py-2.5 rounded-xl transition-all duration-500 ${
                  isVisible ? 'opacity-100 translate-x-0' : 'opacity-20 translate-x-2'
                } ${isCurrent ? `${colors.bg} ${colors.border} border` : ''}`}
              >
                {/* Node */}
                <div className={`absolute left-2.5 w-6 h-6 rounded-full flex items-center justify-center z-10 transition-all ${
                  isVisible ? colors.bg : 'bg-slate-800'
                } ${isCurrent ? 'ring-2 ring-offset-1 ring-offset-slate-900 ' + colors.border : ''}`}>
                  <i className={`fa-solid ${frame.icon} text-[9px] ${isVisible ? colors.text : 'text-slate-600'}`}></i>
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3 mb-0.5">
                    <span className="text-xs text-slate-600 font-mono w-16 shrink-0">{frame.time}</span>
                    <span className={`text-sm font-medium ${isVisible ? colors.text : 'text-slate-600'}`}>
                      {frame.label}
                    </span>
                  </div>
                  <p className={`text-xs ml-[4.75rem] ${isVisible ? 'text-slate-400' : 'text-slate-700'}`}>
                    {frame.detail}
                  </p>
                  {frame.sourceRef && isVisible && (
                    <div className="ml-[4.75rem] mt-1">
                      <span className="text-[10px] text-slate-600 font-mono bg-slate-800/60 px-1.5 py-0.5 rounded">
                        <i className="fa-solid fa-code mr-1 text-[8px]"></i>
                        {frame.sourceRef}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ── Main Component ──────────────────────────────────────────────────
export default function AzraelIncidentLog() {
  const [showContent, setShowContent] = useState(false);
  const [activeTab, setActiveTab] = useState<'forensics' | 'replay' | 'correlation'>('forensics');

  useEffect(() => {
    const timer = setTimeout(() => setShowContent(true), 300);
    return () => clearTimeout(timer);
  }, []);

  const byteDiffs = computeByteDiff(
    incident.telemetry_event.bound_digest,
    incident.telemetry_event.target_digest,
  );
  const mismatchCount = byteDiffs.filter((d) => !d.match).length;
  const firstMismatch = byteDiffs.find((d) => !d.match);

  return (
    <section id="incident" className="py-24 px-6 bg-gradient-to-b from-slate-950 via-red-950/5 to-slate-950">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className={`text-center mb-16 transition-all duration-700 ${showContent ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}>
          <div className="inline-flex items-center gap-2 bg-red-500/10 border border-red-500/30 rounded-full px-4 py-2 mb-6">
            <span className="w-2 h-2 bg-red-400 rounded-full animate-pulse"></span>
            <span className="text-sm text-red-300 font-medium">RUNTIME INCIDENT — SEQUENCE #{incident.sts_sequence_id.toLocaleString()}</span>
          </div>
          <h2 className="text-4xl font-bold mt-3 mb-4">
            <span className="bg-gradient-to-r from-red-400 via-red-300 to-orange-300 bg-clip-text text-transparent">
              Digest Mismatch Forensic Report
            </span>
          </h2>
          <p className="text-slate-400 max-w-2xl mx-auto">
            Full forensic reconstruction of Azrael runtime containment event. Thread revoked at T+0.014ms 
            after constant-time digest comparison detected {mismatchCount} diverged bytes.
          </p>
        </div>

        {/* Status Cards */}
        <div className={`grid grid-cols-2 md:grid-cols-4 gap-4 mb-10 transition-all duration-700 delay-100 ${showContent ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}>
          <div className="bg-slate-900/60 border border-red-500/20 rounded-xl p-5">
            <div className="text-xs text-slate-500 mb-1">Status Code</div>
            <div className="text-2xl font-bold font-mono text-red-400">{incident.status_code}</div>
            <div className="text-[10px] text-red-400/70 mt-1 font-mono truncate">{incident.status_label}</div>
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
            <div className="text-[10px] text-orange-400/70 mt-1 font-mono">UNRATIFIED_HEADER</div>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className={`flex justify-center mb-8 transition-all duration-700 delay-200 ${showContent ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}>
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-1 flex gap-1">
            {[
              { id: 'forensics' as const, label: 'Hex Forensics', icon: 'fa-fingerprint' },
              { id: 'replay' as const, label: 'Containment Replay', icon: 'fa-film' },
              { id: 'correlation' as const, label: 'Risk Correlation', icon: 'fa-chart-line' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  activeTab === tab.id
                    ? 'bg-red-500/20 text-red-300'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <i className={`fa-solid ${tab.icon} mr-2`}></i>
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Tab Content */}
        <div className={`transition-all duration-500 ${showContent ? 'opacity-100' : 'opacity-0'}`}>
          {activeTab === 'forensics' && (
            <div className="space-y-6">
              {/* Quick digest comparison */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
                <h3 className="font-bold text-slate-200 mb-4 flex items-center gap-2">
                  <i className="fa-solid fa-code-compare text-red-400"></i>
                  Raw Digest Comparison
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <div className="text-xs text-cyan-400/60 font-semibold mb-2">BOUND (Expected)</div>
                    <div className="bg-slate-950/80 rounded-lg p-3 border border-slate-800 font-mono text-sm break-all">
                      {incident.telemetry_event.bound_digest.split('').map((c, i) => {
                        const byteIdx = Math.floor(i / 2);
                        const isMismatch = byteDiffs[byteIdx] && !byteDiffs[byteIdx].match;
                        return (
                          <span key={i} className={isMismatch ? 'bg-cyan-500/30 text-cyan-200 rounded px-px' : 'text-slate-400'}>
                            {c}
                          </span>
                        );
                      })}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-red-400/60 font-semibold mb-2">TARGET (Received)</div>
                    <div className="bg-slate-950/80 rounded-lg p-3 border border-slate-800 font-mono text-sm break-all">
                      {incident.telemetry_event.target_digest.split('').map((c, i) => {
                        const byteIdx = Math.floor(i / 2);
                        const isMismatch = byteDiffs[byteIdx] && !byteDiffs[byteIdx].match;
                        return (
                          <span key={i} className={isMismatch ? 'bg-red-500/30 text-red-200 rounded px-px font-bold' : 'text-slate-400'}>
                            {c}
                          </span>
                        );
                      })}
                    </div>
                  </div>
                </div>
                {/* Diff summary */}
                <div className="mt-4 flex items-center gap-4 text-xs">
                  <span className="text-slate-500">
                    <span className="text-red-400 font-bold">{mismatchCount}</span> bytes diverged
                  </span>
                  <span className="text-slate-500">
                    First at offset <span className="text-red-400 font-mono">0x{firstMismatch?.offset.toString(16).toUpperCase().padStart(2, '0')}</span>
                  </span>
                  <span className="text-slate-500">
                    Constant-time: <span className="text-emerald-400">YES</span> (no early exit)
                  </span>
                </div>
              </div>

              {/* Full Hex Dump */}
              <HexDumpViewer />
            </div>
          )}

          {activeTab === 'replay' && (
            <ContainmentReplay />
          )}

          {activeTab === 'correlation' && (
            <div className="space-y-6">
              {/* Risk Impact Grid */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
                <h3 className="font-bold text-slate-200 mb-4 flex items-center gap-2">
                  <i className="fa-solid fa-chart-line text-orange-400"></i>
                  Risk Metric Impact Analysis
                </h3>
                <p className="text-sm text-slate-400 mb-6">
                  How this digest mismatch event correlates to the priced-in risk metrics from Section 2.
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {riskCorrelations.map((rc) => {
                    const colorMap: Record<string, { bar: string; text: string; bg: string; border: string }> = {
                      red: { bar: 'from-red-500 to-red-400', text: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20' },
                      orange: { bar: 'from-orange-500 to-orange-400', text: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20' },
                      yellow: { bar: 'from-yellow-500 to-yellow-400', text: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20' },
                      emerald: { bar: 'from-emerald-500 to-emerald-400', text: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20' },
                    };
                    const colors = colorMap[rc.color];

                    return (
                      <div key={rc.metric} className={`rounded-xl p-5 border ${colors.border} ${colors.bg}`}>
                        <div className="flex items-center justify-between mb-3">
                          <h4 className="font-bold text-slate-200">{rc.metric}</h4>
                          <span className={`text-xs px-2 py-0.5 rounded ${colors.bg} ${colors.text} border ${colors.border}`}>
                            {rc.impact}
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 mb-3">{rc.detail}</p>
                        <div className="flex items-center gap-3">
                          <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                            <div
                              className={`h-full bg-gradient-to-r ${colors.bar} rounded-full`}
                              style={{ width: `${rc.score}%` }}
                            ></div>
                          </div>
                          <span className={`text-sm font-bold font-mono ${colors.text}`}>{rc.score}%</span>
                        </div>
                        <div className="text-[10px] text-slate-600 mt-1">residual assurance score post-incident</div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Cross-reference to deployment */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
                <h3 className="font-bold text-slate-200 mb-4 flex items-center gap-2">
                  <i className="fa-solid fa-link text-cyan-400"></i>
                  Containment → Deployment Response
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="bg-slate-800/30 rounded-xl p-4 border border-slate-700/50">
                    <div className="text-xs text-slate-500 mb-1">Daemon Response</div>
                    <div className="text-sm text-slate-200 font-medium">Watchdog ping suppressed</div>
                    <div className="text-xs text-slate-500 mt-1">No sd_notify("WATCHDOG=1") issued</div>
                  </div>
                  <div className="bg-slate-800/30 rounded-xl p-4 border border-slate-700/50">
                    <div className="text-xs text-slate-500 mb-1">Systemd Action</div>
                    <div className="text-sm text-slate-200 font-medium">Process containment triggered</div>
                    <div className="text-xs text-slate-500 mt-1">WatchdogSec=10s timeout → SIGABRT</div>
                  </div>
                  <div className="bg-slate-800/30 rounded-xl p-4 border border-slate-700/50">
                    <div className="text-xs text-slate-500 mb-1">Recovery</div>
                    <div className="text-sm text-slate-200 font-medium">Restart in 5 seconds</div>
                    <div className="text-xs text-slate-500 mt-1">Restart=on-failure, RestartSec=5s</div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Authority & Ledger (always visible) */}
        <div className={`grid grid-cols-1 md:grid-cols-2 gap-6 mt-10 transition-all duration-700 delay-300 ${showContent ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}>
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
              <div className="flex justify-center gap-1 mt-2">
                {incident.telemetry_event.authority_flags.slice(2).split('').map((hex, i) => (
                  <div key={i} className="text-center">
                    <div className="w-8 h-8 bg-slate-800 rounded flex items-center justify-center font-mono text-sm text-cyan-300 border border-slate-700">
                      {parseInt(hex, 16).toString(2).padStart(4, '0')}
                    </div>
                    <div className="text-[9px] text-slate-600 mt-1">bit {7 - i * 2}-{4 - i * 2}</div>
                  </div>
                ))}
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
                  <div className="text-slate-300 font-medium mt-0.5 font-mono">#{incident.sts_sequence_id.toLocaleString()}</div>
                </div>
                <div className="bg-slate-900/60 rounded-lg p-2">
                  <span className="text-slate-500">Finality</span>
                  <div className="text-emerald-400 font-medium mt-0.5">FINAL</div>
                </div>
              </div>
            </div>
            <div className="text-xs text-slate-500 flex items-center gap-2">
              <i className="fa-solid fa-shield-halved text-indigo-400/50"></i>
              Record is cryptographically sealed — cannot be modified or deleted
            </div>
          </div>
        </div>

        {/* Raw JSON */}
        <div className={`mt-10 transition-all duration-700 delay-500 ${showContent ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}>
          <details className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden group">
            <summary className="px-6 py-4 cursor-pointer flex items-center justify-between hover:bg-slate-800/30 transition-colors">
              <div className="flex items-center gap-3">
                <i className="fa-solid fa-code text-slate-500"></i>
                <span className="text-sm text-slate-400 font-medium">Raw Incident JSON</span>
                <span className="text-xs text-slate-600 font-mono">application/json</span>
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
