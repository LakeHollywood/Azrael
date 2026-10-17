import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';
import BriefingSummary from '../components/BriefingSummary';

describe('BriefingSummary', () => {
  afterEach(cleanup);

  it('renders the document header and ID', () => {
    render(<BriefingSummary partner={null} risk={null} />);
    expect(screen.getByRole('heading', { name: 'Briefing Summary' })).toBeTruthy();
    expect(screen.getByText('Enterprise Design-Partner Briefing')).toBeTruthy();
    expect(screen.getByText('HAP-BRIEF-2026-0115')).toBeTruthy();
  });

  it('shows placeholder warnings when nothing is selected', () => {
    render(<BriefingSummary partner={null} risk={null} />);
    expect(screen.getByText(/No partner selected/)).toBeTruthy();
    expect(screen.getByText(/No risk metric selected/)).toBeTruthy();
  });

  it.each([
    ['fleet', 'Autonomous Fleet Operator'],
    ['defense', 'Defense Prime Contractor'],
    ['enterprise-ai', 'Enterprise AI Platform Leader'],
  ])('maps partner key %s to label "%s"', (key, label) => {
    render(<BriefingSummary partner={key} risk={null} />);
    expect(screen.getByText(label)).toBeTruthy();
    expect(screen.getByText('Profile configured')).toBeTruthy();
    expect(screen.queryByText(/No partner selected/)).toBeNull();
  });

  it.each([
    ['faa-compliance', 'FAA Compliance Risk'],
    ['data-sovereignty', 'Data Sovereignty Risk'],
    ['hallucination', 'Model Hallucination in Critical Loops'],
    ['operational-uptime', 'Operational Uptime Risk'],
  ])('maps risk key %s to label "%s"', (key, label) => {
    render(<BriefingSummary partner={null} risk={key} />);
    expect(screen.getByText(label)).toBeTruthy();
    expect(screen.getByText('Risk metric emphasized')).toBeTruthy();
    expect(screen.queryByText(/No risk metric selected/)).toBeNull();
  });

  it('lists the three numbered next-step actions and both CTA buttons', () => {
    render(<BriefingSummary partner={null} risk={null} />);
    expect(screen.getByText('Confirm partner vertical and risk priority')).toBeTruthy();
    expect(screen.getByText('Review artifact annex highlights')).toBeTruthy();
    expect(screen.getByText('Generate final briefing PDF')).toBeTruthy();
    expect(screen.getByRole('button', { name: /Generate Briefing PDF/i })).toBeTruthy();
    expect(screen.getByRole('button', { name: /Share with Team/i })).toBeTruthy();
  });
});
