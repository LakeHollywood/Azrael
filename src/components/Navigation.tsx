import { useState, useEffect } from 'react';

interface NavigationProps {
  activeSection: string;
  setActiveSection: (section: string) => void;
}

const sections = [
  { id: 'overview', label: 'Overview', icon: 'fa-home' },
  { id: 'partner', label: 'Partner Profile', icon: 'fa-building' },
  { id: 'risk', label: 'Risk Metrics', icon: 'fa-shield-halved' },
  { id: 'artifacts', label: 'Artifacts', icon: 'fa-file-shield' },
  { id: 'azrael', label: 'Azrael Engine', icon: 'fa-skull-crossbones' },
  { id: 'incident', label: 'Incident Log', icon: 'fa-triangle-exclamation' },
  { id: 'summary', label: 'Summary', icon: 'fa-file-lines' },
];

export default function Navigation({ activeSection, setActiveSection }: NavigationProps) {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 50);
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToSection = (id: string) => {
    setActiveSection(id);
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <nav
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled ? 'bg-slate-950/95 backdrop-blur-md shadow-lg shadow-black/20' : 'bg-transparent'
      }`}
    >
      <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center">
            <i className="fa-solid fa-cube text-white text-sm"></i>
          </div>
          <span className="font-bold text-lg tracking-tight">HAP Briefing</span>
        </div>
        <div className="hidden md:flex items-center gap-1">
          {sections.map((section) => (
            <button
              key={section.id}
              onClick={() => scrollToSection(section.id)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                activeSection === section.id
                  ? 'bg-cyan-500/20 text-cyan-300'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
              }`}
            >
              <i className={`fa-solid ${section.icon} mr-2`}></i>
              {section.label}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <span className="hidden sm:inline text-xs text-slate-500 border border-slate-700 px-2 py-1 rounded">
            v2.4
          </span>
          <span className="text-xs text-emerald-400 flex items-center gap-1">
            <span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"></span>
            LIVE
          </span>
        </div>
      </div>
    </nav>
  );
}
