import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import Navigation from '../components/Navigation';

describe('Navigation', () => {
  beforeEach(() => {
    // jsdom does not implement scrollIntoView; stub it.
    Element.prototype.scrollIntoView = vi.fn();
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('renders the brand and all section buttons', () => {
    render(<Navigation activeSection="overview" setActiveSection={vi.fn()} />);

    expect(screen.getByText('HAP Briefing')).toBeTruthy();
    const labels = [
      'Overview',
      'Partner',
      'Risk',
      'Artifacts',
      'Azrael',
      'Incident',
      'Deploy',
      'Summary',
    ];
    for (const label of labels) {
      expect(screen.getByRole('button', { name: new RegExp(label, 'i') })).toBeTruthy();
    }
  });

  it('clicking a nav button calls setActiveSection with the section id and scrolls to it', () => {
    const setActiveSection = vi.fn();
    // Anchor element that scrollToSection looks up by id.
    const anchor = document.createElement('div');
    anchor.id = 'risk';
    anchor.scrollIntoView = vi.fn();
    document.body.appendChild(anchor);

    render(<Navigation activeSection="overview" setActiveSection={setActiveSection} />);
    fireEvent.click(screen.getByRole('button', { name: /Risk/i }));

    expect(setActiveSection).toHaveBeenCalledTimes(1);
    expect(setActiveSection).toHaveBeenCalledWith('risk');
    expect(anchor.scrollIntoView).toHaveBeenCalledWith({ behavior: 'smooth' });

    anchor.remove();
  });

  it('does not throw when the target section element is missing from the DOM', () => {
    const setActiveSection = vi.fn();
    render(<Navigation activeSection="overview" setActiveSection={setActiveSection} />);
    // 'summary' anchor intentionally absent from document.
    fireEvent.click(screen.getByRole('button', { name: /Summary/i }));
    expect(setActiveSection).toHaveBeenCalledWith('summary');
  });

  it('highlights only the active section button', () => {
    render(<Navigation activeSection="azrael" setActiveSection={vi.fn()} />);
    const active = screen.getByRole('button', { name: /Azrael/i });
    const inactive = screen.getByRole('button', { name: /Overview/i });
    expect(active.className).toContain('bg-cyan-500/20');
    expect(inactive.className).not.toContain('bg-cyan-500/20');
  });

  it('shows the version badge and LIVE indicator', () => {
    render(<Navigation activeSection="overview" setActiveSection={vi.fn()} />);
    expect(screen.getByText('v2.4')).toBeTruthy();
    expect(screen.getByText('LIVE')).toBeTruthy();
  });

  it('toggles the scrolled background class on window scroll', () => {
    const { container } = render(
      <Navigation activeSection="overview" setActiveSection={vi.fn()} />
    );
    const nav = container.querySelector('nav')!;
    expect(nav.className).toContain('bg-transparent');

    // Simulate scrolling past the 50px threshold.
    Object.defineProperty(window, 'scrollY', { value: 120, writable: true });
    fireEvent(window, new Event('scroll'));
    expect(nav.className).toContain('bg-slate-950/95');

    // And back to the top.
    Object.defineProperty(window, 'scrollY', { value: 10, writable: true });
    fireEvent(window, new Event('scroll'));
    expect(nav.className).toContain('bg-transparent');
  });
});
