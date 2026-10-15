import { describe, it, expect } from 'vitest';
import { Receptor, AzraelError } from './extracted/receptor';
import type { ReceptorHandle } from './extracted/receptor';

function receptorWithModule(count = 2): Receptor {
  const r = new Receptor(count);
  r.registerModule('sail.telemetry');
  return r;
}

function unwrap<T>(res: { ok: true; value: T } | { ok: false; error: AzraelError }): T {
  if (!res.ok) throw res.error;
  return res.value;
}

describe('AzraelReceptor — ABIDE constitutional invariants', () => {
  it('ABIDE-06: docking defaults to Authority = Revoked', () => {
    const r = receptorWithModule();
    const report = unwrap(r.dockWithReport('sail.telemetry'));
    expect(report.authority).toBe('Revoked');
    expect(r.authorityOf(report.handle)).toBe('Revoked');
    expect(r.topologyState(report.handle)).toBe('Docked');
  });

  it('ABIDE-06: authority stays Revoked across every topology transition', () => {
    const r = receptorWithModule();
    const h = unwrap(r.dock('sail.telemetry'));
    unwrap(r.cleave(h));
    expect(r.authorityOf(h)).toBe('Revoked');
    const h2 = unwrap(r.dock('sail.telemetry'));
    unwrap(r.unmap(h2));
    expect(r.authorityOf(h2)).toBe('Revoked');
  });

  it('unknown module ids are rejected before any socket is touched', () => {
    const r = receptorWithModule();
    const res = r.dock('ghost.module');
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error.code).toBe('AZRAEL_ERR_MODULE_NOT_FOUND');
  });

  it('exhausted socket budget yields NO_CAPACITY', () => {
    const r = receptorWithModule(1);
    unwrap(r.dock('sail.telemetry'));
    const res = r.dock('sail.telemetry');
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error.code).toBe('AZRAEL_ERR_NO_CAPACITY');
  });

  it('ABIDE-02: cleave transitions Docked -> CleavedSocket and is idempotent', () => {
    const r = receptorWithModule();
    const h = unwrap(r.dock('sail.telemetry'));
    expect(unwrap(r.cleave(h))).toBe('CleavedSocket');
    expect(r.topologyState(h)).toBe('CleavedSocket');
    expect(unwrap(r.cleave(h))).toBe('CleavedSocket');
  });

  it('cleaved sockets survive cleavage (binding remains inspectable)', () => {
    const r = receptorWithModule();
    const h = unwrap(r.dock('sail.telemetry'));
    unwrap(r.cleave(h));
    // Socket binding persists — only unmap discards it.
    expect(r.topologyState(h)).toBe('CleavedSocket');
  });

  it('ABIDE-05: unmap is terminal and discards all handle references', () => {
    const r = receptorWithModule();
    const h = unwrap(r.dock('sail.telemetry'));
    expect(unwrap(r.unmap(h))).toBe('Unmapped');
    expect(r.topologyState(h)).toBe('Unmapped');
    const c = r.cleave(h);
    expect(c.ok).toBe(false);
    if (!c.ok) expect(c.error.code).toBe('AZRAEL_ERR_INVALID_HANDLE');
    const u = r.unmap(h);
    expect(u.ok).toBe(false);
    if (!u.ok) expect(u.error.code).toBe('AZRAEL_ERR_INVALID_HANDLE');
  });

  it('stale handles never resolve after a socket is re-bound', () => {
    const r = receptorWithModule();
    const h1: ReceptorHandle = unwrap(r.dock('sail.telemetry'));
    unwrap(r.unmap(h1));
    const h2: ReceptorHandle = unwrap(r.dock('sail.telemetry'));
    expect(h2.generation).toBeGreaterThan(h1.generation);
    expect(r.topologyState(h1)).toBe('Unmapped');
    expect(r.topologyState(h2)).toBe('Docked');
  });

  it('handles from other receptors / fabricated generations are invalid', () => {
    const r = receptorWithModule();
    const forged: ReceptorHandle = { socketId: 0, generation: 99 };
    expect(r.topologyState(forged)).toBe('Unmapped');
    const c = r.cleave(forged);
    expect(c.ok).toBe(false);
    if (!c.ok) expect(c.error.code).toBe('AZRAEL_ERR_INVALID_HANDLE');
  });

  it('topology operations never mutate authority state (A isolation)', () => {
    const r = receptorWithModule();
    const h = unwrap(r.dock('sail.telemetry'));
    const before = r.authorityOf(h);
    unwrap(r.cleave(h));
    unwrap(r.unmap(h));
    expect(r.authorityOf(h)).toBe(before);
    expect(r.authorityOf(h)).toBe('Revoked');
  });

  it('exhaustively: dock succeeds iff module known AND socket free', () => {
    for (const moduleId of ['sail.telemetry', 'ghost.module']) {
      for (const occupied of [false, true]) {
        const r = receptorWithModule(1);
        r.registerModule('other.module');
        if (occupied) unwrap(r.dock('other.module'));
        const res = r.dock(moduleId);
        const shouldSucceed = moduleId === 'sail.telemetry' && !occupied;
        expect(res.ok).toBe(shouldSucceed);
      }
    }
  });
});
