import { useState } from 'react';
import HeroSection from './components/HeroSection';
import PartnerProfile from './components/PartnerProfile';
import RiskMetrics from './components/RiskMetrics';
import ArtifactStatus from './components/ArtifactStatus';
import AzraelEngine from './components/AzraelEngine';
import AzraelIncidentLog from './components/AzraelIncidentLog';
import DeploymentPlan from './components/DeploymentPlan';
import BriefingSummary from './components/BriefingSummary';
import Navigation from './components/Navigation';

export default function App() {
  const [activeSection, setActiveSection] = useState('overview');
  const [selectedPartner, setSelectedPartner] = useState<string | null>(null);
  const [selectedRisk, setSelectedRisk] = useState<string | null>(null);

  return (
    <div className="min-h-screen bg-slate-950 text-white font-sans">
      <Navigation activeSection={activeSection} setActiveSection={setActiveSection} />
      <main>
        <HeroSection />
        <PartnerProfile
          selectedPartner={selectedPartner}
          setSelectedPartner={setSelectedPartner}
        />
        <RiskMetrics
          selectedRisk={selectedRisk}
          setSelectedRisk={setSelectedRisk}
          partnerType={selectedPartner}
        />
        <ArtifactStatus />
        <AzraelEngine />
        <AzraelIncidentLog />
        <DeploymentPlan />
        <BriefingSummary
          partner={selectedPartner}
          risk={selectedRisk}
        />
      </main>
      <footer className="border-t border-slate-800 py-8 px-6 text-center text-slate-500 text-sm">
        <p>Enterprise Design-Partner Briefing Document v2.4 — Confidential</p>
        <p className="mt-1">Hybrid Autonomy Platform • Predicate-Driven Assurance Framework • Azrael Engine v1.2</p>
        <p className="mt-1">SAIL → ABIDE → AZRAEL → A.A.A. • All 5 Sections Complete</p>
      </footer>
    </div>
  );
}
