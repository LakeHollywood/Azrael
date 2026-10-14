import { useEffect, useState } from 'react';

export default function HeroSection() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    setVisible(true);
  }, []);

  return (
    <section id="overview" className="relative min-h-screen flex items-center justify-center overflow-hidden">
      {/* Background effects */}
      <div className="absolute inset-0">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }}></div>
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-indigo-500/5 rounded-full blur-3xl"></div>
      </div>

      {/* Grid pattern */}
      <div className="absolute inset-0 opacity-10"
        style={{
          backgroundImage: 'linear-gradient(rgba(6,182,212,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(6,182,212,0.3) 1px, transparent 1px)',
          backgroundSize: '60px 60px'
        }}
      ></div>

      <div className={`relative z-10 max-w-5xl mx-auto px-6 text-center transition-all duration-1000 ${visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
        <div className="inline-flex items-center gap-2 bg-slate-800/60 border border-slate-700 rounded-full px-4 py-2 mb-8">
          <span className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse"></span>
          <span className="text-sm text-slate-300">Hybrid Autonomy Platform — Next Immediate Action</span>
        </div>

        <h1 className="text-5xl md:text-7xl font-bold tracking-tight mb-6">
          <span className="bg-gradient-to-r from-white via-cyan-100 to-cyan-300 bg-clip-text text-transparent">
            Enterprise Design-Partner
          </span>
          <br />
          <span className="bg-gradient-to-r from-cyan-300 via-blue-400 to-indigo-400 bg-clip-text text-transparent">
            Briefing Document
          </span>
        </h1>

        <p className="text-xl text-slate-400 max-w-3xl mx-auto mb-10 leading-relaxed">
          A predicate-driven assurance framework for autonomous systems. This briefing outlines the hybrid approach 
          combining formal verification with runtime telemetry to deliver priced-in risk metrics for enterprise partners.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-3xl mx-auto mb-12">
          <div className="bg-slate-900/60 border border-slate-700/50 rounded-xl p-5 backdrop-blur-sm">
            <div className="text-3xl font-bold text-cyan-300 mb-1">99.97%</div>
            <div className="text-sm text-slate-400">Predicate Compliance</div>
          </div>
          <div className="bg-slate-900/60 border border-slate-700/50 rounded-xl p-5 backdrop-blur-sm">
            <div className="text-3xl font-bold text-emerald-300 mb-1">&lt;2ms</div>
            <div className="text-sm text-slate-400">Runtime Proof Latency</div>
          </div>
          <div className="bg-slate-900/60 border border-slate-700/50 rounded-xl p-5 backdrop-blur-sm">
            <div className="text-3xl font-bold text-indigo-300 mb-1">3</div>
            <div className="text-sm text-slate-400">Target Partner Verticals</div>
          </div>
        </div>

        <div className="flex flex-wrap justify-center gap-4">
          <a
            href="#partner"
            className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-lg font-medium text-white hover:from-cyan-400 hover:to-blue-500 transition-all shadow-lg shadow-cyan-500/25"
          >
            <i className="fa-solid fa-arrow-down mr-2"></i>
            Configure Briefing
          </a>
          <a
            href="#artifacts"
            className="px-6 py-3 bg-slate-800 border border-slate-700 rounded-lg font-medium text-slate-300 hover:bg-slate-700 hover:text-white transition-all"
          >
            <i className="fa-solid fa-file-shield mr-2"></i>
            View Artifacts
          </a>
        </div>
      </div>
    </section>
  );
}
