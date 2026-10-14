import { useState } from 'react';

const telemetryLogs = [
  {
    timestamp: '2026-01-15T14:23:01.442Z',
    predicate: 'spatial_bounds_check',
    status: 'SATISFIED',
    confidence: 0.997,
    latency_ms: 0.8,
    proof_hash: '0x7a3f...b2e1',
  },
  {
    timestamp: '2026-01-15T14:23:01.443Z',
    predicate: 'collision_avoidance_invariant',
    status: 'SATISFIED',
    confidence: 0.999,
    latency_ms: 1.2,
    proof_hash: '0x9c1d...f4a8',
  },
  {
    timestamp: '2026-01-15T14:23:01.444Z',
    predicate: 'model_output_safety_bound',
    status: 'SATISFIED',
    confidence: 0.994,
    latency_ms: 1.9,
    proof_hash: '0x2e5b...c7d3',
  },
  {
    timestamp: '2026-01-15T14:23:01.445Z',
    predicate: 'data_sovereignty_constraint',
    status: 'SATISFIED',
    confidence: 1.0,
    latency_ms: 0.3,
    proof_hash: '0xf8a2...1b9c',
  },
  {
    timestamp: '2026-01-15T14:23:01.446Z',
    predicate: 'regulatory_compliance_gate',
    status: 'SATISFIED',
    confidence: 0.998,
    latency_ms: 0.6,
    proof_hash: '0x4d7e...a5f2',
  },
  {
    timestamp: '2026-01-15T14:23:02.001Z',
    predicate: 'sensor_fusion_consistency',
    status: 'EVALUATING',
    confidence: 0.87,
    latency_ms: 2.1,
    proof_hash: '0x6b9c...d3e7',
  },
];

const formalProofs = [
  {
    name: 'Spatial Envelope Safety',
    type: 'Coq Proof',
    lines: 2847,
    status: 'verified',
    lastChecked: '2026-01-15',
    theorem: '∀ state ∈ reachable_states, spatial_bounds(state) → safe',
  },
  {
    name: 'Collision Freedom Invariant',
    type: 'TLA+ Specification',
    lines: 1203,
    status: 'verified',
    lastChecked: '2026-01-14',
    theorem: '[] (distance(agent_i, agent_j) > min_safe_distance)',
  },
  {
    name: 'Model Output Bounded Rationality',
    type: 'Lean 4 Proof',
    lines: 4521,
    status: 'verified',
    lastChecked: '2026-01-15',
    theorem: '∀ input, |model_output(input) - optimal(input)| < ε_bound',
  },
  {
    name: 'Liveness & Progress Guarantee',
    type: 'Isabelle/HOL',
    lines: 1892,
    status: 'in-review',
    lastChecked: '2026-01-13',
    theorem: '◇ (goal_reached) ∧ □ (safety_invariant)',
  },
];

export default function ArtifactStatus() {
  const [activeTab, setActiveTab] = useState<'telemetry' | 'proofs'>('telemetry');

  return (
    <section id="artifacts" className="py-24 px-6">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-16">
          <span className="text-cyan-400 text-sm font-semibold tracking-wider uppercase">Section 3</span>
          <h2 className="text-4xl font-bold mt-3 mb-4">Current Artifact Status</h2>
          <p className="text-slate-400 max-w-2xl mx-auto">
            Live-predicate telemetry logs and formal verification proofs. All artifacts are 
            continuously validated and cryptographically attested.
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex justify-center mb-8">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-1 flex gap-1">
            <button
              onClick={() => setActiveTab('telemetry')}
              className={`px-5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'telemetry'
                  ? 'bg-cyan-500/20 text-cyan-300'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <i className="fa-solid fa-satellite-dish mr-2"></i>
              Live Telemetry
            </button>
            <button
              onClick={() => setActiveTab('proofs')}
              className={`px-5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'proofs'
                  ? 'bg-cyan-500/20 text-cyan-300'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <i className="fa-solid fa-certificate mr-2"></i>
              Formal Proofs
            </button>
          </div>
        </div>

        {activeTab === 'telemetry' ? (
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"></span>
                <span className="text-sm text-slate-300 font-medium">Predicate Telemetry Stream</span>
              </div>
              <span className="text-xs text-slate-500">Last 6 entries • Real-time</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-800">
                    <th className="text-left px-6 py-3 text-slate-500 font-medium">Timestamp</th>
                    <th className="text-left px-6 py-3 text-slate-500 font-medium">Predicate</th>
                    <th className="text-left px-6 py-3 text-slate-500 font-medium">Status</th>
                    <th className="text-left px-6 py-3 text-slate-500 font-medium">Confidence</th>
                    <th className="text-left px-6 py-3 text-slate-500 font-medium">Latency</th>
                    <th className="text-left px-6 py-3 text-slate-500 font-medium">Proof Hash</th>
                  </tr>
                </thead>
                <tbody>
                  {telemetryLogs.map((log, i) => (
                    <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                      <td className="px-6 py-3 text-slate-400 font-mono text-xs">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="px-6 py-3 text-cyan-300 font-mono text-xs">{log.predicate}</td>
                      <td className="px-6 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded ${
                          log.status === 'SATISFIED'
                            ? 'bg-emerald-500/10 text-emerald-400'
                            : 'bg-yellow-500/10 text-yellow-400'
                        }`}>
                          {log.status}
                        </span>
                      </td>
                      <td className="px-6 py-3 text-slate-300">{(log.confidence * 100).toFixed(1)}%</td>
                      <td className="px-6 py-3 text-slate-400">{log.latency_ms}ms</td>
                      <td className="px-6 py-3 text-slate-500 font-mono text-xs">{log.proof_hash}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {formalProofs.map((proof) => (
              <div
                key={proof.name}
                className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 hover:border-slate-600 transition-all"
              >
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <h3 className="font-bold text-lg mb-1">{proof.name}</h3>
                    <span className="text-xs text-slate-500">{proof.type} • {proof.lines.toLocaleString()} lines</span>
                  </div>
                  <span className={`text-xs px-2 py-1 rounded ${
                    proof.status === 'verified'
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                      : 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30'
                  }`}>
                    {proof.status === 'verified' ? '✓ Verified' : '⟳ In Review'}
                  </span>
                </div>
                <div className="bg-slate-950/60 rounded-lg p-3 mb-3">
                  <code className="text-xs text-cyan-300 font-mono break-all">{proof.theorem}</code>
                </div>
                <div className="flex items-center justify-between text-xs text-slate-500">
                  <span>Last checked: {proof.lastChecked}</span>
                  <span className="text-cyan-400 cursor-pointer hover:text-cyan-300">
                    View proof →
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
