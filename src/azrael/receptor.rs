//! Azrael Receptor — module docking / cleavage / unmapping topology.
//!
//! This module implements the `AzraelReceptor` contract against the ABIDE
//! constitutional invariants referenced by the trait documentation:
//!
//! * **ABIDE-06** — Physical docking MUST default to `Authority = Revoked`.
//!   A freshly docked module has zero execution authority until an explicit,
//!   out-of-band grant is made by the SovereignEngine. `dock()` can therefore
//!   never produce a handle that carries active authority.
//! * **ABIDE-02** — Topological cleavage (detachment) transitions the module
//!   state `T(M)` to `CleavedSocket`. The socket binding itself survives so
//!   the same physical port may be re-docked; only the logical link is cut.
//! * **ABIDE-05** — Permanent unmapping discards the binding and every live
//!   handle reference to it, transitioning `T(M)` to `Unmapped`.
//! * **Authority isolation** — Neither `cleave()` nor `unmap()` alters the
//!   `SovereignEngine` authority state (`A`). Authority is revoked exactly
//!   at the docking boundary (ABIDE-06); topology operations are orthogonal
//!   to it and must not mutate `A` in either direction.

use std::collections::HashMap;
use std::fmt;

// ── Error surface ───────────────────────────────────────────────────

/// Errors surfaced by receptor operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AzraelError {
    /// The requested module id is unknown to the registry.
    ModuleNotFound,
    /// The handle does not reference a live binding of this receptor.
    InvalidHandle,
    /// The operation is illegal for the handle's current topology state
    /// (e.g. cleaving an already-unmapped socket).
    IllegalTransition,
    /// The receptor has no free sockets available for docking.
    NoCapacity,
}

impl fmt::Display for AzraelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AzraelError::ModuleNotFound => write!(f, "AZRAEL_ERR_MODULE_NOT_FOUND"),
            AzraelError::InvalidHandle => write!(f, "AZRAEL_ERR_INVALID_HANDLE"),
            AzraelError::IllegalTransition => write!(f, "AZRAEL_ERR_ILLEGAL_TRANSITION"),
            AzraelError::NoCapacity => write!(f, "AZRAEL_ERR_NO_CAPACITY"),
        }
    }
}

impl std::error::Error for AzraelError {}

// ── Core taxonomy ───────────────────────────────────────────────────

/// Sovereign authority state (`A`) as seen by the engine. Kept deliberately
/// minimal here: the receptor only reads it, never writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityState {
    Granted,
    Revoked,
}

/// Topological state `T(M)` of a docked module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyState {
    /// Module is physically docked and logically bound to a live socket.
    Docked,
    /// Logical link was cleaved; the socket binding remains re-dockable
    /// (ABIDE-02).
    CleavedSocket,
    /// Binding permanently discarded; all handles unmapped (ABIDE-05).
    Unmapped,
}

/// Opaque token identifying a live receptor binding. Handles are vended by
/// `dock()` and invalidated (permanently) by `unmap()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReceptorHandle {
    pub socket_id: u32,
    pub generation: u64,
}

/// Summary view of a successful docking. Per ABIDE-06 the embedded authority
/// is ALWAYS `Revoked` at construction; there is no constructor that accepts
/// an authority value, so a docked handle cannot carry granted authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockReport {
    pub handle: ReceptorHandle,
    pub module_id: String,
    pub authority: AuthorityState,
}

/// The receptor contract.
pub trait AzraelReceptor {
    /// Binds a module to a new receptor socket.
    /// Constitutional Invariant: Physical docking MUST default to
    /// Authority = Revoked (ABIDE-06).
    fn dock(&mut self, module_id: &str) -> Result<ReceptorHandle, AzraelError>;

    /// Executes topological cleavage (detachment) on an active socket handle.
    /// Transitions T(M) -> CleavedSocket or Unmapped (ABIDE-02 / ABIDE-05).
    /// Note: Does NOT alter SovereignEngine Authority State (A).
    fn cleave(&mut self, handle: &ReceptorHandle) -> Result<TopologyState, AzraelError>;

    /// Permanently unmaps a receptor binding, discarding all handle references.
    fn unmap(&mut self, handle: &ReceptorHandle) -> Result<TopologyState, AzraelError>;

    /// Inspects the current topological state of a handle.
    fn topology_state(&self, handle: &ReceptorHandle) -> TopologyState;
}

// ── Reference implementation ────────────────────────────────────────

struct SocketBinding {
    module_id: String,
    generation: u64,
    topology: TopologyState,
}

/// Concrete receptor with a fixed socket budget and a module allow-list.
pub struct Receptor {
    sockets: Vec<Option<SocketBinding>>,
    /// Monotonic per-socket generation counter; guarantees stale handles from
    /// previous bindings of the same socket never resolve (ABIDE-05:
    /// "discarding ALL handle references").
    generations: Vec<u64>,
    known_modules: HashMap<String, ()>,
}

impl Receptor {
    pub fn new(socket_count: usize) -> Self {
        Self {
            sockets: (0..socket_count).map(|_| None).collect(),
            generations: vec![0; socket_count],
            known_modules: HashMap::new(),
        }
    }

    /// Registry hook: declare that a module exists and may be docked.
    /// In the production engine this consults the signed module manifest;
    /// here it is a simple allow-list so `dock` can fail deterministically.
    pub fn register_module(&mut self, module_id: &str) {
        self.known_modules.insert(module_id.to_string(), ());
    }

    fn find_binding(&self, handle: &ReceptorHandle) -> Option<(usize, &SocketBinding)> {
        let idx = handle.socket_id as usize;
        match self.sockets.get(idx) {
            Some(Some(b)) if b.generation == handle.generation => Some((idx, b)),
            _ => None,
        }
    }

    /// Inspect the module bound to a live handle (None once unmapped/stale).
    pub fn bound_module(&self, handle: &ReceptorHandle) -> Option<&str> {
        self.find_binding(handle).map(|(_, b)| b.module_id.as_str())
    }

    /// Convenience wrapper around `dock` that returns the full ABIDE-06
    /// report (handle + module + authority).
    pub fn dock_with_report(&mut self, module_id: &str) -> Result<DockReport, AzraelError> {
        let handle = self.dock(module_id)?;
        Ok(DockReport {
            handle,
            module_id: module_id.to_string(),
            // ABIDE-06: structural constant — never derived from input.
            authority: AuthorityState::Revoked,
        })
    }

    /// ABIDE-06 accessor: authority observed for a handle. Docking defaults to
    /// `Revoked`; this type exposes no mutation path, so the invariant holds
    /// structurally.
    pub fn authority_of(&self, _handle: &ReceptorHandle) -> AuthorityState {
        AuthorityState::Revoked
    }
}

impl AzraelReceptor for Receptor {
    fn dock(&mut self, module_id: &str) -> Result<ReceptorHandle, AzraelError> {
        if !self.known_modules.contains_key(module_id) {
            return Err(AzraelError::ModuleNotFound);
        }
        let idx = self
            .sockets
            .iter()
            .position(|s| s.is_none())
            .ok_or(AzraelError::NoCapacity)?;

        self.generations[idx] += 1;
        let generation = self.generations[idx];
        self.sockets[idx] = Some(SocketBinding {
            module_id: module_id.to_string(),
            generation,
            topology: TopologyState::Docked,
        });
        Ok(ReceptorHandle {
            socket_id: idx as u32,
            generation,
        })
    }

    fn cleave(&mut self, handle: &ReceptorHandle) -> Result<TopologyState, AzraelError> {
        // Resolve first, then re-borrow mutably — never hold an immutable
        // borrow across a mutation of the same slot.
        let idx = self
            .find_binding(handle)
            .ok_or(AzraelError::InvalidHandle)?
            .0;
        match self.sockets[idx].as_ref().unwrap().topology {
            // ABIDE-02: detach the logical link but keep the socket binding.
            TopologyState::Docked => {
                self.sockets[idx].as_mut().unwrap().topology = TopologyState::CleavedSocket;
                Ok(TopologyState::CleavedSocket)
            }
            // Already detached — cleavage is idempotent on topology.
            TopologyState::CleavedSocket => Ok(TopologyState::CleavedSocket),
            // ABIDE-05 terminal state: nothing left to cleave.
            TopologyState::Unmapped => Err(AzraelError::IllegalTransition),
        }
    }

    fn unmap(&mut self, handle: &ReceptorHandle) -> Result<TopologyState, AzraelError> {
        let idx = self
            .find_binding(handle)
            .ok_or(AzraelError::InvalidHandle)?
            .0;
        // Discard the binding entirely; the bumped generation invalidates every
        // other outstanding handle that pointed at this socket slot.
        self.sockets[idx] = None;
        self.generations[idx] += 1;
        Ok(TopologyState::Unmapped)
    }

    fn topology_state(&self, handle: &ReceptorHandle) -> TopologyState {
        match self.find_binding(handle) {
            Some((_, b)) => b.topology,
            // A handle with no live binding resolves to the terminal state.
            None => TopologyState::Unmapped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receptor_with_module() -> Receptor {
        let mut r = Receptor::new(2);
        r.register_module("sail.telemetry");
        r
    }

    #[test]
    fn dock_defaults_to_revoked_authority_abide06() {
        let mut r = receptor_with_module();
        let report = r.dock_with_report("sail.telemetry").expect("dock succeeds");
        assert_eq!(report.authority, AuthorityState::Revoked);
        assert_eq!(r.authority_of(&report.handle), AuthorityState::Revoked);
        assert_eq!(r.topology_state(&report.handle), TopologyState::Docked);
        assert_eq!(r.bound_module(&report.handle), Some("sail.telemetry"));
    }

    #[test]
    fn dock_unknown_module_fails() {
        let mut r = receptor_with_module();
        assert_eq!(r.dock("ghost.module"), Err(AzraelError::ModuleNotFound));
    }

    #[test]
    fn dock_without_capacity_fails() {
        let mut r = receptor_with_module();
        let _a = r.dock("sail.telemetry").unwrap();
        let _b = r.dock("sail.telemetry").unwrap();
        assert_eq!(r.dock("sail.telemetry"), Err(AzraelError::NoCapacity));
    }

    #[test]
    fn cleave_transitions_to_cleaved_socket_abide02() {
        let mut r = receptor_with_module();
        let h = r.dock("sail.telemetry").unwrap();
        assert_eq!(r.cleave(&h), Ok(TopologyState::CleavedSocket));
        assert_eq!(r.topology_state(&h), TopologyState::CleavedSocket);
        // Idempotent.
        assert_eq!(r.cleave(&h), Ok(TopologyState::CleavedSocket));
    }

    #[test]
    fn unmap_is_terminal_and_discards_handles_abide05() {
        let mut r = receptor_with_module();
        let h = r.dock("sail.telemetry").unwrap();
        assert_eq!(r.unmap(&h), Ok(TopologyState::Unmapped));
        assert_eq!(r.topology_state(&h), TopologyState::Unmapped);
        assert_eq!(r.cleave(&h), Err(AzraelError::InvalidHandle));
        assert_eq!(r.unmap(&h), Err(AzraelError::InvalidHandle));
    }

    #[test]
    fn stale_handle_never_resolves_after_rebind() {
        let mut r = receptor_with_module();
        let h1 = r.dock("sail.telemetry").unwrap();
        r.unmap(&h1).unwrap();
        let h2 = r.dock("sail.telemetry").unwrap();
        assert_ne!(h1, h2, "generation must change across rebinds");
        assert_eq!(r.topology_state(&h1), TopologyState::Unmapped);
        assert_eq!(r.topology_state(&h2), TopologyState::Docked);
    }

    #[test]
    fn topology_ops_do_not_grant_authority() {
        let mut r = receptor_with_module();
        let h = r.dock("sail.telemetry").unwrap();
        r.cleave(&h).unwrap();
        assert_eq!(r.authority_of(&h), AuthorityState::Revoked);
        let h2 = r.dock("sail.telemetry").unwrap();
        r.unmap(&h2).unwrap();
        assert_eq!(r.authority_of(&h2), AuthorityState::Revoked);
    }
}
