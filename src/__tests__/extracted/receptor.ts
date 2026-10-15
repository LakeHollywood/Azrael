// Test-support module: TypeScript mirror of src/azrael/receptor.rs
// (AzraelReceptor trait + Receptor reference implementation).
// Keep in sync with the Rust source. The ABIDE constitutional invariants
// enforced here are:
//   ABIDE-06 — docking ALWAYS yields Authority = Revoked.
//   ABIDE-02 — cleave transitions Docked -> CleavedSocket (socket survives).
//   ABIDE-05 — unmap is terminal: binding discarded, all handles invalidated.
//   Authority isolation — cleave/unmap never mutate SovereignEngine state (A).

export type AuthorityState = 'Granted' | 'Revoked';

export type TopologyState = 'Docked' | 'CleavedSocket' | 'Unmapped';

export type AzraelErrorCode =
  | 'AZRAEL_ERR_MODULE_NOT_FOUND'
  | 'AZRAEL_ERR_INVALID_HANDLE'
  | 'AZRAEL_ERR_ILLEGAL_TRANSITION'
  | 'AZRAEL_ERR_NO_CAPACITY';

export class AzraelError extends Error {
  readonly code: AzraelErrorCode;
  constructor(code: AzraelErrorCode) {
    super(code);
    this.code = code;
  }
}

export interface ReceptorHandle {
  socketId: number;
  generation: number;
}

export interface DockReport {
  handle: ReceptorHandle;
  moduleId: string;
  /** ABIDE-06: structurally constant — dock can never grant authority. */
  authority: AuthorityState;
}

type Result<T> = { ok: true; value: T } | { ok: false; error: AzraelError };

interface SocketBinding {
  moduleId: string;
  generation: number;
  topology: TopologyState;
}

export class Receptor {
  private sockets: (SocketBinding | null)[];
  private generations: number[];
  private knownModules: Set<string>;

  constructor(socketCount: number) {
    this.sockets = Array.from({ length: socketCount }, () => null);
    this.generations = new Array(socketCount).fill(0);
    this.knownModules = new Set();
  }

  registerModule(moduleId: string): void {
    this.knownModules.add(moduleId);
  }

  private findBinding(handle: ReceptorHandle): [number, SocketBinding] | null {
    const b = this.sockets[handle.socketId];
    if (b !== undefined && b !== null && b.generation === handle.generation) {
      return [handle.socketId, b];
    }
    return null;
  }

  /** Binds a module to a free socket. ABIDE-06: returned report ALWAYS has
   *  authority = 'Revoked'; there is no parameter or field path that could
   *  set it otherwise. */
  dock(moduleId: string): Result<ReceptorHandle> {
    if (!this.knownModules.has(moduleId)) {
      return { ok: false, error: new AzraelError('AZRAEL_ERR_MODULE_NOT_FOUND') };
    }
    const idx = this.sockets.findIndex((s) => s === null);
    if (idx === -1) {
      return { ok: false, error: new AzraelError('AZRAEL_ERR_NO_CAPACITY') };
    }
    this.generations[idx] += 1;
    const generation = this.generations[idx];
    this.sockets[idx] = { moduleId, generation, topology: 'Docked' };
    return { ok: true, value: { socketId: idx, generation } };
  }

  dockWithReport(moduleId: string): Result<DockReport> {
    const r = this.dock(moduleId);
    if (!r.ok) return r;
    return {
      ok: true,
      value: {
        handle: r.value,
        moduleId,
        // ABIDE-06: structural constant — never derived from input.
        authority: 'Revoked',
      },
    };
  }

  /** ABIDE-06 accessor. This class exposes no mutation path for authority,
   *  so topology operations can never alter the SovereignEngine state (A). */
  authorityOf(_handle: ReceptorHandle): AuthorityState {
    return 'Revoked';
  }

  /** ABIDE-02 / ABIDE-05: Docked -> CleavedSocket (idempotent); unmapped or
   *  stale handles are rejected. Does NOT touch authority (A). */
  cleave(handle: ReceptorHandle): Result<TopologyState> {
    const found = this.findBinding(handle);
    if (!found) {
      return { ok: false, error: new AzraelError('AZRAEL_ERR_INVALID_HANDLE') };
    }
    const [idx, binding] = found;
    if (binding.topology === 'Docked') {
      this.sockets[idx] = { ...binding, topology: 'CleavedSocket' };
      return { ok: true, value: 'CleavedSocket' };
    }
    if (binding.topology === 'CleavedSocket') {
      return { ok: true, value: 'CleavedSocket' };
    }
    return { ok: false, error: new AzraelError('AZRAEL_ERR_ILLEGAL_TRANSITION') };
  }

  /** ABIDE-05: permanently discards the binding and bumps the generation so
   *  every outstanding handle to this slot becomes invalid. */
  unmap(handle: ReceptorHandle): Result<TopologyState> {
    const found = this.findBinding(handle);
    if (!found) {
      return { ok: false, error: new AzraelError('AZRAEL_ERR_INVALID_HANDLE') };
    }
    const [idx] = found;
    this.sockets[idx] = null;
    this.generations[idx] += 1;
    return { ok: true, value: 'Unmapped' };
  }

  topologyState(handle: ReceptorHandle): TopologyState {
    const found = this.findBinding(handle);
    return found ? found[1].topology : 'Unmapped';
  }
}
