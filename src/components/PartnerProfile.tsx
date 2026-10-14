interface PartnerProfileProps {
  selectedPartner: string | null;
  setSelectedPartner: (partner: string | null) => void;
}

const partners = [
  {
    id: 'fleet',
    title: 'Autonomous Fleet Operator',
    icon: 'fa-truck-fast',
    color: 'from-cyan-400 to-cyan-600',
    description: 'Last-mile delivery, long-haul trucking, or urban mobility platforms operating at scale.',
    metrics: [
      { label: 'Fleet Size', value: '500-10,000+' },
      { label: 'Regulatory Focus', value: 'FMCSA / NHTSA' },
      { label: 'Key Concern', value: 'Operational Uptime' },
    ],
    priorities: [
      'FAA Part 107 / FMCSA compliance automation',
      'Real-time fleet-wide predicate monitoring',
      'Insurance risk reduction through formal assurance',
    ],
  },
  {
    id: 'defense',
    title: 'Defense Prime Contractor',
    icon: 'fa-shield-halved',
    color: 'from-indigo-400 to-indigo-600',
    description: 'Tier-1 defense integrators requiring MIL-STD-882 and DO-178C compliant assurance.',
    metrics: [
      { label: 'Clearance Level', value: 'TS/SCI' },
      { label: 'Regulatory Focus', value: 'MIL-STD-882E' },
      { label: 'Key Concern', value: 'Data Sovereignty' },
    ],
    priorities: [
      'Air-gapped formal verification pipelines',
      'Supply chain integrity proofs',
      'Adversarial robustness guarantees',
    ],
  },
  {
    id: 'enterprise-ai',
    title: 'Enterprise AI Platform Leader',
    icon: 'fa-brain',
    color: 'from-violet-400 to-purple-600',
    description: 'Fortune 500 AI/ML platform teams deploying models in safety-critical decision loops.',
    metrics: [
      { label: 'Model Count', value: '100-10,000+' },
      { label: 'Regulatory Focus', value: 'EU AI Act / SOC2' },
      { label: 'Key Concern', value: 'Hallucination in Critical Loops' },
    ],
    priorities: [
      'Runtime predicate enforcement on LLM outputs',
      'Audit trail for regulatory compliance',
      'Model drift detection with formal bounds',
    ],
  },
];

export default function PartnerProfile({ selectedPartner, setSelectedPartner }: PartnerProfileProps) {
  return (
    <section id="partner" className="py-24 px-6">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-16">
          <span className="text-cyan-400 text-sm font-semibold tracking-wider uppercase">Section 1</span>
          <h2 className="text-4xl font-bold mt-3 mb-4">Target Partner Profile</h2>
          <p className="text-slate-400 max-w-2xl mx-auto">
            Select the partner vertical to tailor the briefing. Each profile maps to specific compliance 
            frameworks, risk models, and artifact requirements.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {partners.map((partner) => (
            <button
              key={partner.id}
              onClick={() => setSelectedPartner(selectedPartner === partner.id ? null : partner.id)}
              className={`text-left p-6 rounded-2xl border transition-all duration-300 ${
                selectedPartner === partner.id
                  ? 'bg-slate-800/80 border-cyan-500/50 shadow-lg shadow-cyan-500/10 scale-[1.02]'
                  : 'bg-slate-900/40 border-slate-800 hover:border-slate-600 hover:bg-slate-800/40'
              }`}
            >
              <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${partner.color} flex items-center justify-center mb-4`}>
                <i className={`fa-solid ${partner.icon} text-white text-lg`}></i>
              </div>
              <h3 className="text-xl font-bold mb-2">{partner.title}</h3>
              <p className="text-sm text-slate-400 mb-4">{partner.description}</p>

              <div className="space-y-2 mb-4">
                {partner.metrics.map((metric) => (
                  <div key={metric.label} className="flex justify-between text-sm">
                    <span className="text-slate-500">{metric.label}</span>
                    <span className="text-slate-300 font-medium">{metric.value}</span>
                  </div>
                ))}
              </div>

              {selectedPartner === partner.id && (
                <div className="mt-4 pt-4 border-t border-slate-700">
                  <p className="text-xs text-cyan-400 font-semibold mb-2">KEY PRIORITIES:</p>
                  <ul className="space-y-1">
                    {partner.priorities.map((p) => (
                      <li key={p} className="text-xs text-slate-400 flex items-start gap-2">
                        <i className="fa-solid fa-check text-cyan-400 mt-0.5 text-[10px]"></i>
                        {p}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </button>
          ))}
        </div>
      </div>
    </section>
  );
}
