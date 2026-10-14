interface RiskMetricsProps {
  selectedRisk: string | null;
  setSelectedRisk: (risk: string | null) => void;
  partnerType: string | null;
}

const riskMetrics = [
  {
    id: 'faa-compliance',
    title: 'FAA Compliance Risk',
    icon: 'fa-plane',
    severity: 'critical',
    score: 94,
    description: 'Regulatory exposure for autonomous aerial operations under Part 107 and proposed Part 108 frameworks.',
    factors: [
      { name: 'Airworthiness Predicate Coverage', value: 97, status: 'pass' },
      { name: 'BVLOS Operational Envelope', value: 88, status: 'pass' },
      { name: 'Detect-and-Avoid Formal Proof', value: 91, status: 'pass' },
      { name: 'Maintenance Interval Compliance', value: 96, status: 'pass' },
    ],
    partners: ['fleet', 'defense'],
  },
  {
    id: 'data-sovereignty',
    title: 'Data Sovereignty Risk',
    icon: 'fa-globe',
    severity: 'high',
    score: 87,
    description: 'Risk of cross-border data flows violating ITAR, GDPR, or national security requirements.',
    factors: [
      { name: 'Geographic Predicate Bounds', value: 99, status: 'pass' },
      { name: 'Encryption at Rest/Transit', value: 100, status: 'pass' },
      { name: 'Supply Chain Provenance', value: 82, status: 'warning' },
      { name: 'Personnel Access Controls', value: 91, status: 'pass' },
    ],
    partners: ['defense', 'enterprise-ai'],
  },
  {
    id: 'hallucination',
    title: 'Model Hallucination in Critical Loops',
    icon: 'fa-triangle-exclamation',
    severity: 'critical',
    score: 78,
    description: 'Probability of LLM-generated outputs violating safety predicates in real-time decision paths.',
    factors: [
      { name: 'Output Predicate Enforcement', value: 95, status: 'pass' },
      { name: 'Confidence Bound Calibration', value: 84, status: 'warning' },
      { name: 'Fallback Predicate Activation', value: 92, status: 'pass' },
      { name: 'Drift Detection Latency', value: 76, status: 'warning' },
    ],
    partners: ['enterprise-ai', 'fleet'],
  },
  {
    id: 'operational-uptime',
    title: 'Operational Uptime Risk',
    icon: 'fa-clock',
    severity: 'medium',
    score: 91,
    description: 'Risk of predicate-gated shutdowns causing unacceptable fleet downtime.',
    factors: [
      { name: 'Predicate False Positive Rate', value: 98, status: 'pass' },
      { name: 'Graceful Degradation Coverage', value: 94, status: 'pass' },
      { name: 'Recovery Time Objective', value: 89, status: 'pass' },
      { name: 'Redundancy Predicate Depth', value: 87, status: 'pass' },
    ],
    partners: ['fleet', 'enterprise-ai'],
  },
];

const severityColors: Record<string, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/30',
  high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
};

export default function RiskMetrics({ selectedRisk, setSelectedRisk, partnerType }: RiskMetricsProps) {
  const filteredMetrics = partnerType
    ? riskMetrics.filter((m) => m.partners.includes(partnerType))
    : riskMetrics;

  return (
    <section id="risk" className="py-24 px-6 bg-slate-900/30">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-16">
          <span className="text-cyan-400 text-sm font-semibold tracking-wider uppercase">Section 2</span>
          <h2 className="text-4xl font-bold mt-3 mb-4">Priced-In Risk Metrics</h2>
          <p className="text-slate-400 max-w-2xl mx-auto">
            The most compelling risk metric for your partner vertical. Each metric is backed by 
            formal proofs and continuously validated through live-predicate telemetry.
          </p>
          {partnerType && (
            <div className="mt-4 inline-flex items-center gap-2 bg-cyan-500/10 border border-cyan-500/30 rounded-full px-4 py-2">
              <i className="fa-solid fa-filter text-cyan-400 text-xs"></i>
              <span className="text-sm text-cyan-300">Filtered for: {partnerType.replace('-', ' ')}</span>
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {filteredMetrics.map((metric) => (
            <div
              key={metric.id}
              onClick={() => setSelectedRisk(selectedRisk === metric.id ? null : metric.id)}
              className={`cursor-pointer rounded-2xl border p-6 transition-all duration-300 ${
                selectedRisk === metric.id
                  ? 'bg-slate-800/80 border-cyan-500/50 shadow-lg shadow-cyan-500/10'
                  : 'bg-slate-900/60 border-slate-800 hover:border-slate-600'
              }`}
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-slate-800 flex items-center justify-center">
                    <i className={`fa-solid ${metric.icon} text-cyan-400`}></i>
                  </div>
                  <div>
                    <h3 className="font-bold text-lg">{metric.title}</h3>
                    <span className={`inline-block text-xs px-2 py-0.5 rounded border mt-1 ${severityColors[metric.severity]}`}>
                      {metric.severity.toUpperCase()}
                    </span>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-3xl font-bold text-white">{metric.score}</div>
                  <div className="text-xs text-slate-500">assurance score</div>
                </div>
              </div>

              <p className="text-sm text-slate-400 mb-4">{metric.description}</p>

              {selectedRisk === metric.id && (
                <div className="space-y-3 mt-4 pt-4 border-t border-slate-700">
                  {metric.factors.map((factor) => (
                    <div key={factor.name}>
                      <div className="flex justify-between text-sm mb-1">
                        <span className="text-slate-300">{factor.name}</span>
                        <span className={factor.status === 'pass' ? 'text-emerald-400' : 'text-yellow-400'}>
                          {factor.value}%
                        </span>
                      </div>
                      <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-1000 ${
                            factor.status === 'pass'
                              ? 'bg-gradient-to-r from-emerald-500 to-cyan-400'
                              : 'bg-gradient-to-r from-yellow-500 to-orange-400'
                          }`}
                          style={{ width: `${factor.value}%` }}
                        ></div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
