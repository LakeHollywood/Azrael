interface BriefingSummaryProps {
  partner: string | null;
  risk: string | null;
}

const partnerLabels: Record<string, string> = {
  fleet: 'Autonomous Fleet Operator',
  defense: 'Defense Prime Contractor',
  'enterprise-ai': 'Enterprise AI Platform Leader',
};

const riskLabels: Record<string, string> = {
  'faa-compliance': 'FAA Compliance Risk',
  'data-sovereignty': 'Data Sovereignty Risk',
  hallucination: 'Model Hallucination in Critical Loops',
  'operational-uptime': 'Operational Uptime Risk',
};

export default function BriefingSummary({ partner, risk }: BriefingSummaryProps) {
  return (
    <section id="summary" className="py-24 px-6 bg-slate-900/30">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-16">
          <span className="text-cyan-400 text-sm font-semibold tracking-wider uppercase">Section 4</span>
          <h2 className="text-4xl font-bold mt-3 mb-4">Briefing Summary</h2>
          <p className="text-slate-400 max-w-2xl mx-auto">
            Auto-generated summary based on your selections. This section will be included in the 
            final Enterprise Design-Partner Briefing Document.
          </p>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-8">
          {/* Document Header */}
          <div className="border-b border-slate-800 pb-6 mb-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-2xl font-bold">Enterprise Design-Partner Briefing</h3>
                <p className="text-slate-500 text-sm mt-1">Hybrid Autonomy Platform • Predicate-Driven Assurance</p>
              </div>
              <div className="text-right">
                <div className="text-xs text-slate-500">Document ID</div>
                <div className="font-mono text-sm text-slate-300">HAP-BRIEF-2026-0115</div>
              </div>
            </div>
          </div>

          {/* Configuration Status */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="bg-slate-800/40 rounded-xl p-5 border border-slate-700/50">
              <div className="flex items-center gap-2 mb-3">
                <i className="fa-solid fa-building text-cyan-400"></i>
                <span className="text-sm font-semibold text-slate-300">Target Partner</span>
              </div>
              {partner ? (
                <div>
                  <div className="text-lg font-bold text-white">{partnerLabels[partner]}</div>
                  <div className="text-xs text-emerald-400 mt-1">
                    <i className="fa-solid fa-check-circle mr-1"></i>
                    Profile configured
                  </div>
                </div>
              ) : (
                <div className="text-slate-500 text-sm">
                  <i className="fa-solid fa-circle-exclamation mr-1 text-yellow-400"></i>
                  No partner selected — briefing will cover all verticals
                </div>
              )}
            </div>

            <div className="bg-slate-800/40 rounded-xl p-5 border border-slate-700/50">
              <div className="flex items-center gap-2 mb-3">
                <i className="fa-solid fa-shield-halved text-cyan-400"></i>
                <span className="text-sm font-semibold text-slate-300">Primary Risk Metric</span>
              </div>
              {risk ? (
                <div>
                  <div className="text-lg font-bold text-white">{riskLabels[risk]}</div>
                  <div className="text-xs text-emerald-400 mt-1">
                    <i className="fa-solid fa-check-circle mr-1"></i>
                    Risk metric emphasized
                  </div>
                </div>
              ) : (
                <div className="text-slate-500 text-sm">
                  <i className="fa-solid fa-circle-exclamation mr-1 text-yellow-400"></i>
                  No risk metric selected — all metrics will be presented equally
                </div>
              )}
            </div>
          </div>

          {/* Next Steps */}
          <div className="bg-gradient-to-r from-cyan-500/5 to-blue-500/5 border border-cyan-500/20 rounded-xl p-6">
            <h4 className="font-bold text-lg mb-4 flex items-center gap-2">
              <i className="fa-solid fa-rocket text-cyan-400"></i>
              Next Immediate Action
            </h4>
            <div className="space-y-3">
              <div className="flex items-start gap-3">
                <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-300 flex items-center justify-center text-xs font-bold shrink-0">1</span>
                <div>
                  <p className="text-slate-300 text-sm font-medium">Confirm partner vertical and risk priority</p>
                  <p className="text-slate-500 text-xs mt-0.5">Select your target profile above to tailor the document</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-300 flex items-center justify-center text-xs font-bold shrink-0">2</span>
                <div>
                  <p className="text-slate-300 text-sm font-medium">Review artifact annex highlights</p>
                  <p className="text-slate-500 text-xs mt-0.5">Latest telemetry and formal proof summaries are ready for inclusion</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-300 flex items-center justify-center text-xs font-bold shrink-0">3</span>
                <div>
                  <p className="text-slate-300 text-sm font-medium">Generate final briefing PDF</p>
                  <p className="text-slate-500 text-xs mt-0.5">Document will be formatted for executive distribution with cryptographic attestation</p>
                </div>
              </div>
            </div>

            <div className="mt-6 flex flex-wrap gap-3">
              <button className="px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-lg text-sm font-medium text-white hover:from-cyan-400 hover:to-blue-500 transition-all shadow-lg shadow-cyan-500/25">
                <i className="fa-solid fa-file-pdf mr-2"></i>
                Generate Briefing PDF
              </button>
              <button className="px-5 py-2.5 bg-slate-800 border border-slate-700 rounded-lg text-sm font-medium text-slate-300 hover:bg-slate-700 hover:text-white transition-all">
                <i className="fa-solid fa-share-nodes mr-2"></i>
                Share with Team
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
