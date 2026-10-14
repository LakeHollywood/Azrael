import { useState, useEffect } from 'react';

// ── Systemd Unit File Syntax Highlighter ────────────────────────────
function highlightSystemdLine(line: string) {
  // Comments
  if (line.trim().startsWith('#')) {
    return <span className="text-slate-500 italic">{line}</span>;
  }

  // Section headers like [Unit], [Service], [Install]
  if (/^\[.+\]$/.test(line.trim())) {
    return <span className="text-cyan-300 font-bold">{line}</span>;
  }

  // Key=Value pairs
  const eqIndex = line.indexOf('=');
  if (eqIndex > 0 && !line.trim().startsWith('#')) {
    const key = line.slice(0, eqIndex);
    const value = line.slice(eqIndex);
    return (
      <>
        <span className="text-purple-400">{key}</span>
        <span className="text-slate-500">=</span>
        <span className="text-emerald-300">{value.slice(1)}</span>
      </>
    );
  }

  return <span className="text-slate-300">{line}</span>;
}

// ── Architecture Diagram Nodes ──────────────────────────────────────
interface DiagramNode {
  id: string;
  label: string;
  sublabel: string;
  icon: string;
  color: string;
  x: number;
  y: number;
}

const diagramNodes: DiagramNode[] = [
  { id: 'sensor', label: 'NOAA / Sensor Stream', sublabel: 'Live Telemetry', icon: 'fa-satellite-dish', color: 'from-cyan-500 to-cyan-700', x: 5, y: 15 },
  { id: 'daemon', label: 'Ingestion Daemon', sublabel: 'Python/Rust Async', icon: 'fa-gears', color: 'from-blue-500 to-blue-700', x: 35, y: 15 },
  { id: 'azrael', label: 'AZRAEL FFI Guard', sublabel: 'Predicate Engine', icon: 'fa-shield-halved', color: 'from-red-500 to-red-700', x: 65, y: 15 },
  { id: 'ledger', label: 'A.A.A. Ledger', sublabel: 'Immutable Audit', icon: 'fa-book', color: 'from-indigo-500 to-indigo-700', x: 65, y: 60 },
  { id: 'watchdog', label: 'Systemd Watchdog', sublabel: 'Hardware Keep-Alive', icon: 'fa-heart-pulse', color: 'from-emerald-500 to-emerald-700', x: 5, y: 60 },
];

// ── Pipeline Steps ──────────────────────────────────────────────────
const pipelineSteps = [
  {
    num: 1,
    title: 'Ingestion & Buffering',
    description: 'Asynchronous Python/Rust ingestion workers pull real-time data streams and construct event payloads.',
    icon: 'fa-download',
    color: 'cyan',
    detail: 'Non-blocking I/O with bounded ring buffers. Backpressure via async channels.',
  },
  {
    num: 2,
    title: 'Digest Pre-Verification',
    description: 'Incoming streams are bound to temporal sequence counters provided by the STS time engine.',
    icon: 'fa-fingerprint',
    color: 'blue',
    detail: 'Monotonic sequence IDs ensure replay resistance. Digests computed before FFI crossing.',
  },
  {
    num: 3,
    title: 'C-ABI Assertion',
    description: 'Payloads are passed directly across the FFI boundary to azrael_eval_predicate().',
    icon: 'fa-plug',
    color: 'red',
    detail: 'Zero-copy pointer passing. No serialization overhead. Panic containment via catch_unwind.',
  },
  {
    num: 4,
    title: 'Watchdog Ping',
    description: 'Upon successful verification (AZRAEL_OK), the daemon issues a systemd keep-alive ping.',
    icon: 'fa-heart-pulse',
    color: 'emerald',
    detail: 'sd_notify("WATCHDOG=1") confirms liveness. 10s watchdog interval enforced.',
  },
  {
    num: 5,
    title: 'Containment State',
    description: 'If AZRAEL returns error codes, the daemon suppresses the watchdog ping, triggering systemd containment.',
    icon: 'fa-lock',
    color: 'orange',
    detail: 'BOUNDARY_VIOLATION or DIGEST_MISMATCH → no ping → systemd isolates/restarts → breach logged to A.A.A.',
  },
];

// ── Hardware Specs ──────────────────────────────────────────────────
const hwSpecs = [
  { label: 'Node Designation', value: 'Mobile Edge Compute Unit', sub: 'Vehicle / Splinter Mobile Node', icon: 'fa-microchip' },
  { label: 'Compute Architecture', value: 'x86_64 / ARM64', sub: 'Multi-core processor', icon: 'fa-server' },
  { label: 'Runtime Sandbox', value: 'OpenShell / WASM', sub: 'WebAssembly isolate engine', icon: 'fa-cube' },
  { label: 'Telemetry Input', value: 'Async Data Streams', sub: 'NOAA, environmental, agentic IPC', icon: 'fa-tower-broadcast' },
  { label: 'Hardware Watchdog', value: 'Systemd Integrated', sub: 'Tied to AZRAEL containment states', icon: 'fa-heart-pulse' },
];

// ── Section Summary ─────────────────────────────────────────────────
const proposalSections = [
  { num: 1, title: 'Executive Summary & Strategic Value Proposition', icon: 'fa-bullseye', color: 'from-cyan-500 to-cyan-700', status: 'complete' },
  { num: 2, title: 'Core Value Invariants & Proof Requirements', icon: 'fa-infinity', color: 'from-blue-500 to-blue-700', status: 'complete' },
  { num: 3, title: 'System Architecture & Taxonomy Specification', icon: 'fa-sitemap', color: 'from-indigo-500 to-indigo-700', status: 'complete', sub: 'SAIL → ABIDE → AZRAEL → A.A.A.' },
  { num: 4, title: 'Threat Vector & Telemetry Evidence Matrix', icon: 'fa-crosshairs', color: 'from-red-500 to-red-700', status: 'complete' },
  { num: 5, title: 'Deployment & Edge Integration Plan', icon: 'fa-rocket', color: 'from-emerald-500 to-emerald-700', status: 'active' },
];

// ── Main Component ──────────────────────────────────────────────────
export default function DeploymentPlan() {
  const [activeNode, setActiveNode] = useState<string | null>(null);
  const [activePipelineStep, setActivePipelineStep] = useState<number | null>(null);
  const [animatedNodes, setAnimatedNodes] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setAnimatedNodes(true), 200);
    return () => clearTimeout(timer);
  }, []);

  const systemdLines = `[Unit]
Description=SAIL / AZRAEL Continuous Telemetry Ingestion Daemon
After=network.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/sail_telemetry_daemon --config /etc/sail/config.toml
Restart=on-failure
RestartSec=5s

# Systemd Watchdog Integration
WatchdogSec=10s

# Isolation and Security Capabilities
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true
ReadOnlyPaths=/
ReadWritePaths=/var/log/sail /var/run/sail

[Install]
WantedBy=multi-user.target`;

  return (
    <section id="deployment" className="py-24 px-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="text-center mb-16">
          <span className="text-emerald-400 text-sm font-semibold tracking-wider uppercase">Section 5</span>
          <h2 className="text-4xl font-bold mt-3 mb-4">
            <span className="bg-gradient-to-r from-emerald-300 via-cyan-300 to-blue-300 bg-clip-text text-transparent">
              Deployment & Edge Integration Plan
            </span>
          </h2>
          <p className="text-slate-400 max-w-3xl mx-auto">
            Dual deployment architecture for enterprise cloud orchestrators and mobile/air-gapped edge compute nodes. 
            Zero external runtime dependencies outside standard C-ABI and Rust system calls.
          </p>
        </div>

        {/* ── 5.1 Architecture Diagram ─────────────────────────── */}
        <div className="mb-16">
          <div className="flex items-center gap-3 mb-6">
            <span className="text-xs font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-1 rounded">5.1</span>
            <h3 className="text-xl font-bold text-slate-200">Deployment Architecture</h3>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
            <div className="px-6 py-3 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"></span>
                <span className="text-sm text-slate-400">Edge Node / Field Deployment Topology</span>
              </div>
              <span className="text-xs text-slate-600 font-mono">AIR-GAPPED COMPATIBLE</span>
            </div>

            {/* Interactive Architecture Diagram */}
            <div className="relative p-8 min-h-[400px]">
              {/* Connection Lines (SVG) */}
              <svg className="absolute inset-0 w-full h-full pointer-events-none" viewBox="0 0 100 80" preserveAspectRatio="none">
                {/* Sensor → Daemon */}
                <line x1="22" y1="25" x2="35" y2="25" stroke="rgb(6,182,212)" strokeWidth="0.3" strokeDasharray="1,0.5" opacity="0.5">
                  <animate attributeName="stroke-dashoffset" from="0" to="-3" dur="1.5s" repeatCount="indefinite" />
                </line>
                {/* Daemon → AZRAEL */}
                <line x1="52" y1="25" x2="65" y2="25" stroke="rgb(239,68,68)" strokeWidth="0.3" strokeDasharray="1,0.5" opacity="0.5">
                  <animate attributeName="stroke-dashoffset" from="0" to="-3" dur="1.5s" repeatCount="indefinite" />
                </line>
                {/* AZRAEL → Ledger (down) */}
                <line x1="72" y1="35" x2="72" y2="60" stroke="rgb(99,102,241)" strokeWidth="0.3" strokeDasharray="1,0.5" opacity="0.5">
                  <animate attributeName="stroke-dashoffset" from="0" to="-3" dur="2s" repeatCount="indefinite" />
                </line>
                {/* Watchdog → AZRAEL (feedback) */}
                <path d="M 22 65 Q 45 80 65 35" fill="none" stroke="rgb(16,185,129)" strokeWidth="0.3" strokeDasharray="1,0.5" opacity="0.5">
                  <animate attributeName="stroke-dashoffset" from="0" to="-3" dur="2s" repeatCount="indefinite" />
                </path>
                {/* Arrow markers */}
                <polygon points="34,24 34,26 36,25" fill="rgb(6,182,212)" opacity="0.6" />
                <polygon points="64,24 64,26 66,25" fill="rgb(239,68,68)" opacity="0.6" />
                <polygon points="71,59 73,59 72,61" fill="rgb(99,102,241)" opacity="0.6" />
              </svg>

              {/* Nodes */}
              {diagramNodes.map((node) => (
                <div
                  key={node.id}
                  onMouseEnter={() => setActiveNode(node.id)}
                  onMouseLeave={() => setActiveNode(null)}
                  className={`absolute cursor-pointer transition-all duration-500 ${
                    animatedNodes ? 'opacity-100 scale-100' : 'opacity-0 scale-90'
                  } ${activeNode === node.id ? 'z-20 scale-110' : 'z-10'}`}
                  style={{ left: `${node.x}%`, top: `${node.y}%`, width: '28%', transitionDelay: `${diagramNodes.indexOf(node) * 100}ms` }}
                >
                  <div className={`bg-slate-800/80 border rounded-xl p-4 backdrop-blur-sm transition-all ${
                    activeNode === node.id
                      ? 'border-emerald-500/50 shadow-lg shadow-emerald-500/10'
                      : 'border-slate-700/50 hover:border-slate-600'
                  }`}>
                    <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${node.color} flex items-center justify-center mb-2`}>
                      <i className={`fa-solid ${node.icon} text-white text-sm`}></i>
                    </div>
                    <div className="text-sm font-bold text-slate-200">{node.label}</div>
                    <div className="text-xs text-slate-500">{node.sublabel}</div>
                    {activeNode === node.id && node.id === 'azrael' && (
                      <div className="mt-2 text-xs text-red-400 bg-red-500/10 rounded px-2 py-1 border border-red-500/20">
                        <i className="fa-solid fa-shield-halved mr-1"></i>
                        Containment gate — all predicates enforced here
                      </div>
                    )}
                    {activeNode === node.id && node.id === 'watchdog' && (
                      <div className="mt-2 text-xs text-emerald-400 bg-emerald-500/10 rounded px-2 py-1 border border-emerald-500/20">
                        <i className="fa-solid fa-heart-pulse mr-1"></i>
                        Suppresses ping on AZRAEL error → systemd containment
                      </div>
                    )}
                    {activeNode === node.id && node.id === 'ledger' && (
                      <div className="mt-2 text-xs text-indigo-400 bg-indigo-500/10 rounded px-2 py-1 border border-indigo-500/20">
                        <i className="fa-solid fa-book mr-1"></i>
                        Immutable audit trail — PASS_PUBLISHED_V1_1
                      </div>
                    )}
                  </div>
                </div>
              ))}

              {/* Edge boundary box */}
              <div className="absolute inset-4 border-2 border-dashed border-slate-700/50 rounded-2xl pointer-events-none">
                <span className="absolute -top-3 left-6 bg-slate-900 px-2 text-xs text-slate-600 font-mono">
                  EDGE NODE BOUNDARY
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* ── 5.2 Hardware Reference Profile ───────────────────── */}
        <div className="mb-16">
          <div className="flex items-center gap-3 mb-6">
            <span className="text-xs font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-1 rounded">5.2</span>
            <h3 className="text-xl font-bold text-slate-200">Edge Compute Node Hardware Reference</h3>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
            {hwSpecs.map((spec) => (
              <div key={spec.label} className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 hover:border-slate-600 transition-all group">
                <i className={`fa-solid ${spec.icon} text-emerald-400/60 text-lg mb-3 group-hover:text-emerald-400 transition-colors`}></i>
                <div className="text-xs text-slate-500 mb-1">{spec.label}</div>
                <div className="text-sm font-bold text-slate-200">{spec.value}</div>
                <div className="text-xs text-slate-500 mt-1">{spec.sub}</div>
              </div>
            ))}
          </div>

          <div className="mt-4 bg-slate-900/40 border border-slate-800 rounded-xl p-4">
            <p className="text-sm text-slate-400">
              <i className="fa-solid fa-flask text-emerald-400/60 mr-2"></i>
              <strong className="text-slate-300">Validation criteria:</strong> Deterministic boundary safety under variable physical conditions — 
              thermal load, power draw, and high-throughput telemetry streams.
            </p>
          </div>
        </div>

        {/* ── 5.3 Systemd Integration ──────────────────────────── */}
        <div className="mb-16">
          <div className="flex items-center gap-3 mb-6">
            <span className="text-xs font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-1 rounded">5.3</span>
            <h3 className="text-xl font-bold text-slate-200">Systemd Integration & Daemon Configuration</h3>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
            {/* Systemd Unit File */}
            <div className="lg:col-span-3 bg-slate-950 border border-slate-800 rounded-2xl overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800 bg-slate-900/60">
                <div className="flex items-center gap-3">
                  <div className="flex gap-1.5">
                    <span className="w-3 h-3 rounded-full bg-red-500/80"></span>
                    <span className="w-3 h-3 rounded-full bg-yellow-500/80"></span>
                    <span className="w-3 h-3 rounded-full bg-emerald-500/80"></span>
                  </div>
                  <span className="text-sm text-slate-400 font-mono">sail-edge-daemon.service</span>
                </div>
                <span className="text-xs text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                  systemd
                </span>
              </div>
              <div className="p-4 font-mono text-sm max-h-[420px] overflow-y-auto">
                {systemdLines.split('\n').map((line, i) => (
                  <div key={i} className="flex hover:bg-slate-800/30 group">
                    <span className="w-8 shrink-0 text-right pr-3 text-slate-700 select-none text-xs leading-6 group-hover:text-slate-500">
                      {i + 1}
                    </span>
                    <span className="flex-1 leading-6">
                      {highlightSystemdLine(line)}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Security Capabilities */}
            <div className="lg:col-span-2 space-y-4">
              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5">
                <h4 className="font-bold text-sm text-slate-300 mb-4 flex items-center gap-2">
                  <i className="fa-solid fa-lock text-emerald-400"></i>
                  Security Isolation
                </h4>
                <div className="space-y-3">
                  {[
                    { key: 'ProtectSystem', value: 'strict', desc: 'Full filesystem read-only mount' },
                    { key: 'ProtectHome', value: 'true', desc: 'Home directories inaccessible' },
                    { key: 'NoNewPrivileges', value: 'true', desc: 'Privilege escalation blocked' },
                    { key: 'PrivateTmp', value: 'true', desc: 'Isolated /tmp namespace' },
                    { key: 'ReadOnlyPaths', value: '/', desc: 'Root filesystem immutable' },
                  ].map((cap) => (
                    <div key={cap.key} className="flex items-center gap-3 bg-slate-800/30 rounded-lg p-3">
                      <span className="w-2 h-2 rounded-full bg-emerald-400 shrink-0"></span>
                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-mono text-emerald-300">{cap.key}={cap.value}</div>
                        <div className="text-xs text-slate-500 truncate">{cap.desc}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5">
                <h4 className="font-bold text-sm text-slate-300 mb-3 flex items-center gap-2">
                  <i className="fa-solid fa-heart-pulse text-emerald-400"></i>
                  Watchdog Contract
                </h4>
                <div className="bg-slate-950/60 rounded-lg p-3 border border-slate-800 font-mono text-xs space-y-1">
                  <div className="text-slate-500"># On AZRAEL_OK:</div>
                  <div className="text-emerald-400">sd_notify("WATCHDOG=1")</div>
                  <div className="text-slate-500 mt-2"># On AZRAEL error:</div>
                  <div className="text-red-400"># Suppress ping → containment</div>
                  <div className="text-slate-500 mt-2"># Interval:</div>
                  <div className="text-cyan-300">WatchdogSec=10s</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ── 5.4 Telemetry Ingestion Pipeline ─────────────────── */}
        <div className="mb-16">
          <div className="flex items-center gap-3 mb-6">
            <span className="text-xs font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-1 rounded">5.4</span>
            <h3 className="text-xl font-bold text-slate-200">Continuous Telemetry Ingestion Workflow</h3>
          </div>

          <div className="relative">
            {/* Connection line */}
            <div className="absolute top-1/2 left-0 right-0 h-0.5 bg-gradient-to-r from-cyan-500/30 via-blue-500/30 to-emerald-500/30 -translate-y-1/2 hidden lg:block"></div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
              {pipelineSteps.map((step) => {
                const colorMap: Record<string, { bg: string; border: string; text: string; icon: string }> = {
                  cyan: { bg: 'bg-cyan-500/10', border: 'border-cyan-500/30', text: 'text-cyan-300', icon: 'text-cyan-400' },
                  blue: { bg: 'bg-blue-500/10', border: 'border-blue-500/30', text: 'text-blue-300', icon: 'text-blue-400' },
                  red: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-300', icon: 'text-red-400' },
                  emerald: { bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', text: 'text-emerald-300', icon: 'text-emerald-400' },
                  orange: { bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-300', icon: 'text-orange-400' },
                };
                const colors = colorMap[step.color];
                const isActive = activePipelineStep === step.num;

                return (
                  <div
                    key={step.num}
                    onMouseEnter={() => setActivePipelineStep(step.num)}
                    onMouseLeave={() => setActivePipelineStep(null)}
                    className={`relative bg-slate-900/60 border rounded-2xl p-5 transition-all duration-300 cursor-pointer ${
                      isActive
                        ? `${colors.border} shadow-lg scale-[1.02] z-10`
                        : 'border-slate-800 hover:border-slate-600'
                    }`}
                  >
                    {/* Step number badge */}
                    <div className={`absolute -top-3 -left-2 w-7 h-7 rounded-full ${colors.bg} border ${colors.border} flex items-center justify-center`}>
                      <span className={`text-xs font-bold ${colors.text}`}>{step.num}</span>
                    </div>

                    <i className={`fa-solid ${step.icon} ${colors.icon} text-lg mb-3 mt-1`}></i>
                    <h4 className="text-sm font-bold text-slate-200 mb-2">{step.title}</h4>
                    <p className="text-xs text-slate-400 leading-relaxed">{step.description}</p>

                    {isActive && (
                      <div className={`mt-3 pt-3 border-t ${colors.border} text-xs ${colors.text} bg-slate-950/40 rounded-lg p-2`}>
                        <i className="fa-solid fa-info-circle mr-1"></i>
                        {step.detail}
                      </div>
                    )}

                    {/* Arrow between steps (visible on large screens) */}
                    {step.num < 5 && (
                      <div className="hidden lg:block absolute -right-3 top-1/2 -translate-y-1/2 z-20">
                        <i className={`fa-solid fa-chevron-right ${colors.icon} text-xs`}></i>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Containment flow note */}
          <div className="mt-6 bg-red-500/5 border border-red-500/20 rounded-xl p-4 flex items-start gap-3">
            <i className="fa-solid fa-triangle-exclamation text-red-400 mt-0.5"></i>
            <div className="text-sm text-slate-400">
              <strong className="text-red-300">Containment trigger:</strong> If step 3 returns <code className="text-red-400 bg-red-500/10 px-1 rounded">AZRAEL_ERR_BOUNDARY_VIOLATION</code> or <code className="text-red-400 bg-red-500/10 px-1 rounded">AZRAEL_ERR_DIGEST_MISMATCH</code>, 
              the daemon suppresses the step 4 watchdog ping, triggering systemd process containment and logging the breach to the A.A.A. ledger.
            </div>
          </div>
        </div>

        {/* ── 5.5 Complete Proposal Summary ────────────────────── */}
        <div>
          <div className="flex items-center gap-3 mb-6">
            <span className="text-xs font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-1 rounded">5.5</span>
            <h3 className="text-xl font-bold text-slate-200">Comprehensive Proposal Deliverable Summary</h3>
          </div>

          <div className="bg-gradient-to-br from-slate-900/80 to-slate-800/40 border border-slate-700 rounded-2xl p-8">
            <div className="text-center mb-8">
              <div className="inline-flex items-center gap-2 bg-emerald-500/10 border border-emerald-500/30 rounded-full px-4 py-2 mb-4">
                <i className="fa-solid fa-check-double text-emerald-400"></i>
                <span className="text-sm text-emerald-300 font-medium">All 5 Sections Complete</span>
              </div>
              <h4 className="text-2xl font-bold text-white mb-2">Technical Proposal Package</h4>
              <p className="text-slate-400 text-sm">Ready for distribution to program leads or technical reviewers</p>
            </div>

            <div className="space-y-3">
              {proposalSections.map((section) => (
                <div
                  key={section.num}
                  className={`flex items-center gap-4 p-4 rounded-xl border transition-all ${
                    section.status === 'active'
                      ? 'bg-emerald-500/5 border-emerald-500/30'
                      : 'bg-slate-800/30 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${section.color} flex items-center justify-center shrink-0`}>
                    <i className={`fa-solid ${section.icon} text-white text-sm`}></i>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-slate-500 font-mono">Section {section.num}</span>
                      <span className={`text-xs px-1.5 py-0.5 rounded ${
                        section.status === 'complete'
                          ? 'bg-emerald-500/10 text-emerald-400'
                          : 'bg-cyan-500/10 text-cyan-400'
                      }`}>
                        {section.status === 'complete' ? '✓ Complete' : '● Current'}
                      </span>
                    </div>
                    <div className="text-sm font-medium text-slate-200 mt-0.5">{section.title}</div>
                    {section.sub && (
                      <div className="text-xs text-slate-500 mt-0.5 font-mono">{section.sub}</div>
                    )}
                  </div>
                  <i className="fa-solid fa-chevron-right text-slate-700"></i>
                </div>
              ))}
            </div>

            {/* Action buttons */}
            <div className="mt-8 flex flex-wrap gap-3 justify-center">
              <button className="px-6 py-3 bg-gradient-to-r from-emerald-500 to-cyan-600 rounded-lg font-medium text-white hover:from-emerald-400 hover:to-cyan-500 transition-all shadow-lg shadow-emerald-500/25">
                <i className="fa-solid fa-file-pdf mr-2"></i>
                Export Full Proposal PDF
              </button>
              <button className="px-6 py-3 bg-slate-800 border border-slate-700 rounded-lg font-medium text-slate-300 hover:bg-slate-700 hover:text-white transition-all">
                <i className="fa-solid fa-share-nodes mr-2"></i>
                Share with Reviewers
              </button>
              <button className="px-6 py-3 bg-slate-800 border border-slate-700 rounded-lg font-medium text-slate-300 hover:bg-slate-700 hover:text-white transition-all">
                <i className="fa-solid fa-code-branch mr-2"></i>
                View Source Repository
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
