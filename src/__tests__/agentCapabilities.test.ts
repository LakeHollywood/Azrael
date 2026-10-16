import { describe, expect, it } from 'vitest';
import type { ExecutionContext, TaskDefinition } from '@/lib/agent/types';
import {
  canExecute,
  clampRiskScore,
  deriveChildContext,
  isGateSubset,
  validateTaskDelegation,
} from '@/lib/agent/capabilities';

const parentContext = (overrides?: Partial<ExecutionContext>): ExecutionContext => ({
  identity: { type: 'agent', id: 'agent_root', rootAgentId: 'agent_root' },
  capabilities: { allowedGates: ['gate.deploy', 'gate.read'], maxAutonomousRiskScore: 15 },
  audit: {
    traceId: 'trace-001',
    state: 'APPROVED',
    actor: 'agent_root',
    timestamp: new Date('2026-10-17T00:00:00Z').toISOString(),
  },
  ...overrides,
});

describe('clampRiskScore', () => {
  it('clamps into [0, 100] and fails closed on non-finite input', () => {
    expect(clampRiskScore(-5)).toBe(0);
    expect(clampRiskScore(42)).toBe(42);
    expect(clampRiskScore(101)).toBe(100);
    expect(clampRiskScore(Number.NaN)).toBe(100);
  });
});

describe('isGateSubset', () => {
  it('detects subset relationships', () => {
    expect(isGateSubset(['a', 'b'], ['a'])).toBe(true);
    expect(isGateSubset(['a', 'b'], ['c'])).toBe(false);
    expect(isGateSubset([], [])).toBe(true);
  });
});

describe('validateTaskDelegation', () => {
  const task = (over?: Partial<TaskDefinition>): TaskDefinition => ({
    name: 'sub-task',
    requestedGates: ['gate.read'],
    requestedMaxRiskScore: 10,
    ...over,
  });

  it('accepts a strictly narrower request', () => {
    expect(validateTaskDelegation(parentContext(), task()).ok).toBe(true);
  });

  it('rejects gates outside the parent allowlist', () => {
    const res = validateTaskDelegation(parentContext(), task({ requestedGates: ['gate.wipe'] }));
    expect(res.ok).toBe(false);
    expect(res.errors.join(' ')).toMatch(/outside parent scope/);
  });

  it('rejects a higher risk ceiling than the parent cap', () => {
    const res = validateTaskDelegation(parentContext(), task({ requestedMaxRiskScore: 16 }));
    expect(res.ok).toBe(false);
    expect(res.errors.join(' ')).toMatch(/exceeds/);
  });

  it('allows an equal risk ceiling', () => {
    expect(validateTaskDelegation(parentContext(), task({ requestedMaxRiskScore: 15 })).ok).toBe(true);
  });

  it('fails closed when the parent has no traceId', () => {
    const parent = parentContext();
    parent.audit.traceId = '';
    const res = validateTaskDelegation(parent, task());
    expect(res.ok).toBe(false);
    expect(res.errors.join(' ')).toMatch(/fail closed/);
  });
});

describe('deriveChildContext', () => {
  it('never expands privileges beyond the parent', () => {
    const parent = parentContext();
    const child = deriveChildContext(parent, {
      name: 'sub-task',
      requestedGates: ['gate.read', 'gate.rogue'], // rogue filtered out
      requestedMaxRiskScore: 999,                   // capped to parent's 15
    }, 'task_42');

    expect(child.identity).toEqual({ type: 'task', id: 'task_42', rootAgentId: 'agent_root' });
    expect(child.capabilities.allowedGates).toEqual(['gate.read']);
    expect(child.capabilities.maxAutonomousRiskScore).toBe(15);
    expect(child.audit.state).toBe('PENDING');
    expect(child.audit.traceId).toBe(parent.audit.traceId);
  });
});

describe('canExecute', () => {
  it('enforces gate membership, risk cap, and trace presence', () => {
    const ctx = parentContext();
    expect(canExecute(ctx, 'gate.read', 10)).toBe(true);
    expect(canExecute(ctx, 'gate.wipe', 10)).toBe(false);
    expect(canExecute(ctx, 'gate.read', 16)).toBe(false);
    const untraced = parentContext();
    untraced.audit.traceId = '';
    expect(canExecute(untraced, 'gate.read', 10)).toBe(false);
  });
});
