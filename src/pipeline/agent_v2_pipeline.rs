//! agent_v2_pipeline.rs — Rust port of the approval-gate risk engine and the
//! gated action-execution pipeline (Agent v2).
//!
//! This module is a faithful, dependency-free reimplementation of:
//!   * `approval_gate/risk.py`  (clamp_score / determine_policy / apply_overrides
//!     / create_approval_record) — band table, floors, and override semantics
//!     are pinned to match the Python source exactly, including the
//!     escalation-only invariant (floors may raise a score, never relax it),
//!   * the TypeScript `src/lib/approvalGates.ts` `gated()` lifecycle
//!     (pending -> ApprovalRequired, approved -> execute once, expired/denied
//!     -> terminal rejection, executed -> blocked re-run).
//!
//! The parity contract with the Python engine is asserted in
//! tests/test_risk_thresholds.py-style cases below (`#[cfg(test)] mod tests`),
//! including the pinned refund case: composite score 70 => DUAL_APPROVAL.
//!
//! No external crates: std only, so this compiles anywhere a Rust toolchain
//! exists (`rustc --test src/pipeline/agent_v2_pipeline.rs`).

use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
#[cfg(test)]
use std::cell::RefCell;
#[cfg(test)]
use std::thread_local;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Risk model
// ---------------------------------------------------------------------------

/// Minimum approval requirement for an operation. Mirrors
/// `ApprovalPolicy` in `approval_gate/risk.py`. The serialized name is the
/// lowercase snake-case band value (e.g. `"dual_approval"`) used in audit
/// records by both the Python and TypeScript engines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApprovalPolicy {
    Autonomous,
    SingleApproval,
    SeniorApproval,
    DualApproval,
    Restricted,
}

impl ApprovalPolicy {
    /// Serialized band name, byte-for-byte identical to Python's
    /// `ApprovalPolicy.value`.
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalPolicy::Autonomous => "autonomous",
            ApprovalPolicy::SingleApproval => "single_approval",
            ApprovalPolicy::SeniorApproval => "senior_approval",
            ApprovalPolicy::DualApproval => "dual_approval",
            ApprovalPolicy::Restricted => "restricted",
        }
    }

    /// Minimum number of human approvals implied by the band.
    /// AUTONOMOUS executes without sign-off; RESTRICTED is denied by default
    /// (break-glass only) and is represented here as `usize::MAX` so that any
    /// concrete `required_approvals` setting can be checked against it.
    pub fn required_approvals(&self) -> usize {
        match self {
            ApprovalPolicy::Autonomous => 0,
            ApprovalPolicy::SingleApproval => 1,
            ApprovalPolicy::SeniorApproval => 1,
            ApprovalPolicy::DualApproval => 2,
            ApprovalPolicy::Restricted => usize::MAX,
        }
    }
}

impl fmt::Display for ApprovalPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Inclusive lower bound of each policy band, ascending. A score maps to the
/// band with the highest lower bound it reaches. Identical to Python's
/// `POLICY_THRESHOLDS`.
pub const POLICY_THRESHOLDS: [(f64, ApprovalPolicy); 5] = [
    (0.0, ApprovalPolicy::Autonomous),
    (20.0, ApprovalPolicy::SingleApproval),
    (40.0, ApprovalPolicy::SeniorApproval),
    (60.0, ApprovalPolicy::DualApproval),
    (80.0, ApprovalPolicy::Restricted),
];

pub const RISK_SCORE_MIN: f64 = 0.0;
pub const RISK_SCORE_MAX: f64 = 100.0;

/// Authz-impacting operations can never execute below a two-approver bar.
pub const AUTHZ_RISK_FLOOR: f64 = 60.0;
/// Self-modification of the gate always lands in RESTRICTED.
pub const GATE_MODIFICATION_RISK_FLOOR: f64 = RISK_SCORE_MAX;

/// Constrain a raw risk score to the valid `[0, 100]` range.
/// (Python: `clamp_score`.)
pub fn clamp_score(score: f64) -> f64 {
    if score < RISK_SCORE_MIN {
        RISK_SCORE_MIN
    } else if score > RISK_SCORE_MAX {
        RISK_SCORE_MAX
    } else {
        score
    }
}

/// Return the approval policy required for a given risk score. Band
/// boundaries are inclusive at the lower edge (exactly 60 => DUAL_APPROVAL).
/// (Python: `determine_policy`.)
pub fn determine_policy(score: f64) -> ApprovalPolicy {
    let clamped = clamp_score(score);
    let mut policy = POLICY_THRESHOLDS[0].1;
    for &(lower_bound, candidate) in POLICY_THRESHOLDS.iter() {
        if clamped >= lower_bound {
            policy = candidate;
        } else {
            break;
        }
    }
    policy
}

/// One table-based override rule: `(lower_bound, new_score)`. Applies when
/// `score >= lower_bound`; the rule with the greatest key wins (most
/// specific matching rule), matching Python's tuple-ordering tie-break.
pub type OverrideRule = (f64, f64);

/// Options for `apply_overrides`, mirroring the keyword arguments of the
/// Python function.
#[derive(Clone, Copy, Debug, Default)]
pub struct OverrideOptions<'a> {
    pub affects_authz: bool,
    pub modifies_approval_gate: bool,
    pub overrides: Option<&'a HashMap<String, OverrideRule>>,
}

/// Return the effective risk score after applying escalation floors.
///
/// Semantics pinned to Python `apply_overrides`:
/// 1. table-based `overrides` are applied first (best-matching rule wins);
/// 2. `affects_authz || modifies_approval_gate` raises the score to at least
///    `AUTHZ_RISK_FLOOR` (escalation only — `max`, never relax);
/// 3. `modifies_approval_gate` forces the score to at least
///    `GATE_MODIFICATION_RISK_FLOOR` (100 => RESTRICTED);
/// 4. the final score is clamped to `[0, 100]`.
pub fn apply_overrides(risk_score: f64, opts: &OverrideOptions<'_>) -> f64 {
    let mut score = risk_score;

    if let Some(overrides) = opts.overrides {
        // Deterministic iteration: sort keys so behavior does not depend on
        // HashMap ordering. Python keeps dict insertion order, but the
        // winner is selected by max((lower_bound, new_score)) among matching
        // rules, which is order-independent for distinct keys; we replicate
        // the same selection.
        let mut names: Vec<&String> = overrides.keys().collect();
        names.sort();
        let mut best_key: Option<(f64, f64)> = None;
        let mut best_value: Option<f64> = None;
        for name in names {
            let &(lower_bound, new_score) = &overrides[name];
            if score >= lower_bound {
                let key = (lower_bound, new_score);
                if best_key.map_or(true, |bk| key > bk) {
                    best_key = Some(key);
                    best_value = Some(new_score);
                }
            }
        }
        if let Some(v) = best_value {
            score = v;
        }
    }

    if opts.affects_authz || opts.modifies_approval_gate {
        score = score.max(AUTHZ_RISK_FLOOR);
    }
    if opts.modifies_approval_gate {
        score = score.max(GATE_MODIFICATION_RISK_FLOOR);
    }

    clamp_score(score)
}

// ---------------------------------------------------------------------------
// Audit record
// ---------------------------------------------------------------------------

/// The artifact persisted for every gated operation (Python:
/// `create_approval_record`). Guarantees: `risk_score` is clamped, and
/// `approval_policy` always matches `determine_policy(risk_score)` — a record
/// can never claim a laxer policy than its score requires.
#[derive(Clone, Debug, PartialEq)]
pub struct ApprovalRecord {
    pub record_id: String,
    pub operation: String,
    pub actor: String,
    pub risk_score: f64,
    pub approval_policy: String,
    pub created_at: String,
    pub extra: HashMap<String, String>,
}

/// Injectable clock returning ISO-8601 UTC text (for deterministic tests).
pub type ClockFn = fn() -> String;
/// Injectable ID factory (for deterministic tests).
pub type IdFactory = fn() -> String;

fn system_clock_utc() -> String {
    // Minimal UTC stamp without external crates: seconds since epoch in
    // fixed format. Exact calendar formatting lives in the TS/Python layers;
    // this preserves record shape and monotonicity.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}Z")
}

fn uuid_like_id() -> String {
    // Non-cryptographic unique-ish id from time + a static counter; real
    // deployments inject `id_factory`.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("rec-{nanos:x}-{n:x}")
}

/// Build an audit entry pairing a recorded score with its policy.
/// (Python: `create_approval_record`; `clock`/`id_factory` injectable.)
pub fn create_approval_record(
    risk_score: f64,
    operation: &str,
    actor: &str,
    clock: Option<ClockFn>,
    id_factory: Option<IdFactory>,
    extra: Option<HashMap<String, String>>,
) -> ApprovalRecord {
    let clamped = clamp_score(risk_score);
    ApprovalRecord {
        record_id: id_factory.unwrap_or(uuid_like_id)(),
        operation: operation.to_string(),
        actor: actor.to_string(),
        risk_score: clamped,
        approval_policy: determine_policy(clamped).as_str().to_string(),
        created_at: clock.unwrap_or(system_clock_utc)(),
        extra: extra.unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------
// Gate definition & registry
// ---------------------------------------------------------------------------

/// Component risk dimensions. The composite score is their sum, clamped to
/// 0..=100. Mirrors the `risk` block of `defineGate` in
/// `src/lib/approvalGates.ts` and the refund gate profile in
/// `src/actions/financial/refund.ts`.
#[derive(Clone, Copy, Debug, Default)]
pub struct RiskProfile {
    pub action_risk: f64,
    pub asset_criticality: f64,
    pub blast_radius: f64,
    pub privilege_escalation: f64,
    pub model_confidence_penalty: f64,
    pub reversibility: f64,
    pub anomaly_multiplier: f64,
}

impl RiskProfile {
    /// Composite score = sum of components, clamped to [0, 100].
    pub fn composite(&self) -> f64 {
        clamp_score(
            self.action_risk
                + self.asset_criticality
                + self.blast_radius
                + self.privilege_escalation
                + self.model_confidence_penalty
                + self.reversibility
                + self.anomaly_multiplier,
        )
    }
}

/// Status of an approval request inside the registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Executed,
}

/// A persisted approval request produced when a gated action is blocked.
#[derive(Clone, Debug, PartialEq)]
pub struct ApprovalRequest {
    pub id: String,
    pub gate_id: String,
    pub idempotency_key: String,
    pub risk_score: f64,
    pub policy: ApprovalPolicy,
    pub required_approvals: usize,
    pub approvals: Vec<String>, // actor ids who approved
    pub deny_reason: Option<String>,
    pub status: RequestStatus,
    pub created_at_ms: u64,
    pub expiry_ms: u64,
}

/// Errors surfaced by the gated pipeline instead of panicking.
#[derive(Clone, Debug, PartialEq)]
pub enum GateError {
    /// Execution yielded to HITL: a pending approval request was created.
    ApprovalRequired(ApprovalRequest),
    /// The request resolved to denial or expiry — terminal, do not retry.
    ApprovalRejected { request_id: String, reason: String },
    /// The requesting role is not on the gate's allowlist.
    RoleNotAllowed { role: String, allowlist: Vec<String> },
    /// The action already executed under this idempotency key.
    AlreadyExecuted { request_id: String },
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GateError::ApprovalRequired(r) => write!(
                f,
                "approval required: {} (score {}, policy {}, needs {})",
                r.id, r.risk_score, r.policy, r.required_approvals
            ),
            GateError::ApprovalRejected { request_id, reason } => {
                write!(f, "approval rejected for {request_id}: {reason}")
            }
            GateError::RoleNotAllowed { role, allowlist } => {
                write!(f, "role {role} not in allowlist {allowlist:?}")
            }
            GateError::AlreadyExecuted { request_id } => {
                write!(f, "action already executed under request {request_id}")
            }
        }
    }
}

impl std::error::Error for GateError {}

/// Static configuration of a gate (analogue of registry config in
/// `defineGate`). Overrides are escalation-only: `required_approvals` can be
/// raised above the band minimum but never relaxed below it.
#[derive(Clone, Debug)]
pub struct Gate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub risk: RiskProfile,
    pub risk_score: f64,
    pub policy: ApprovalPolicy,
    pub required_approvals: usize,
    pub allowlist_roles: Vec<String>,
    pub expiry_ms: u64,
}

#[derive(Clone, Debug)]
pub struct GateBuilder {
    inner: Gate,
    override_required: Option<usize>,
}

impl GateBuilder {
    pub fn required_approvals(mut self, n: usize) -> Self {
        self.override_required = Some(n);
        self
    }
    pub fn allowlist(mut self, roles: &[&str]) -> Self {
        self.inner.allowlist_roles = roles.iter().map(|s| s.to_string()).collect();
        self
    }
    pub fn expiry_ms(mut self, ms: u64) -> Self {
        self.inner.expiry_ms = ms;
        self
    }
    /// Finalize. Derives `risk_score`/`policy` from the profile and applies
    /// the escalation-only floor on `required_approvals`.
    pub fn build(mut self) -> Gate {
        self.inner.risk_score = self.inner.risk.composite();
        self.inner.policy = determine_policy(self.inner.risk_score);
        let band_min = self.inner.policy.required_approvals();
        let requested = self.override_required.unwrap_or(band_min);
        self.inner.required_approvals = requested.max(band_min);
        self.inner
    }
}

/// `defineGate(...)` analogue.
pub fn define_gate(
    id: &str,
    name: &str,
    description: &str,
    risk: RiskProfile,
) -> GateBuilder {
    GateBuilder {
        inner: Gate {
            id: id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            risk,
            risk_score: 0.0,
            policy: ApprovalPolicy::Autonomous,
            required_approvals: 0,
            allowlist_roles: vec![],
            expiry_ms: 15 * 60 * 1000,
        },
        override_required: None,
    }
}

/// Registry seam. Implementations persist requests across process restarts
/// (databases, queues). The in-memory implementation below is enough for
/// single-process pipelines and tests.
pub trait Registry {
    fn get_by_idempotency_key(&mut self, key: &str) -> Option<&ApprovalRequest>;
    fn insert(&mut self, request: ApprovalRequest) -> ApprovalRequest;
    fn get_mut(&mut self, id: &str) -> Option<&mut ApprovalRequest>;
}

/// Simple in-memory registry keyed by request id, with an idempotency index.
#[derive(Default)]
pub struct InMemoryRegistry {
    by_id: HashMap<String, ApprovalRequest>,
    by_key: HashMap<String, String>,
}

impl Registry for InMemoryRegistry {
    fn get_by_idempotency_key(&mut self, key: &str) -> Option<&ApprovalRequest> {
        self.by_key.get(key).and_then(|id| self.by_id.get(id))
    }
    fn insert(&mut self, request: ApprovalRequest) -> ApprovalRequest {
        self.by_key.insert(request.idempotency_key.clone(), request.id.clone());
        self.by_id.insert(request.id.clone(), request.clone());
        request
    }
    fn get_mut(&mut self, id: &str) -> Option<&mut ApprovalRequest> {
        self.by_id.get_mut(id)
    }
}

/// Time source for expiry checks (injectable for tests).
pub trait NowMs {
    fn now_ms(&self) -> u64;
}

impl<F: Fn() -> u64> NowMs for F {
    fn now_ms(&self) -> u64 {
        (self)()
    }
}

pub fn system_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Pipeline: gated()
// ---------------------------------------------------------------------------

/// Identity of the caller attempting the action.
#[derive(Clone, Debug)]
pub struct Caller {
    pub actor: String,
    pub role: String,
}

/// Per-invocation context handed to the raw action and the idempotency-key
/// builder.
#[derive(Clone, Debug)]
pub struct Invocation<A> {
    pub args: A,
    /// Unique per-attempt nonce appended to the idempotency key so retries
    /// after denial/expiry create fresh requests rather than colliding with
    /// the terminal one (fix #3 from the refund review).
    pub nonce: String,
}

/// Outcome of a successful execution path.
#[derive(Clone, Debug)]
pub struct Executed<R> {
    pub result: R,
    pub request_id: String,
    /// True when the band required zero approvals and no request round-trip
    /// occurred beyond bookkeeping.
    pub autonomous: bool,
}

/// The `gated(gate, raw_action)` wrapper. Owns a registry and clock; enforces
/// the full lifecycle before invoking `raw`:
///
/// * existing PENDING request under the idempotency key -> still pending =>
///   `ApprovalRequired` (no duplicate request); APPROVED => execute and mark
///   EXECUTED; DENIED/EXPIRED => `ApprovalRejected` (terminal); EXECUTED =>
///   `AlreadyExecuted` (blocked silent re-run).
/// * no existing request: AUTONOMOUS band => execute immediately.
/// * otherwise create a request and return `ApprovalRequired` until humans
///   resolve it.
/// * role allowlist is enforced before anything else.
pub struct GatedAction<A, R, Reg, Raw, KeyFn>
where
    Raw: Fn(&Invocation<A>) -> Result<R, GateError>,
    KeyFn: Fn(&A) -> String,
{
    pub gate: Gate,
    registry: Reg,
    raw: Raw,
    idempotency_key: KeyFn,
    now: Box<dyn NowMs>,
    id_factory: Box<dyn Fn() -> String>,
    _args: PhantomData<A>,
    _result: PhantomData<R>,
}

impl<A, R, Reg, Raw, KeyFn> GatedAction<A, R, Reg, Raw, KeyFn>
where
    Reg: Registry,
    Raw: Fn(&Invocation<A>) -> Result<R, GateError>,
    KeyFn: Fn(&A) -> String,
{
    pub fn new(
        gate: Gate,
        registry: Reg,
        raw: Raw,
        idempotency_key: KeyFn,
        now: impl NowMs + 'static,
    ) -> Self {
        Self {
            gate,
            registry,
            raw,
            idempotency_key,
            now: Box::new(now),
            id_factory: Box::new(uuid_like_id),
            _args: PhantomData,
            _result: PhantomData,
        }
    }

    pub fn with_id_factory(mut self, f: impl Fn() -> String + 'static) -> Self {
        self.id_factory = Box::new(f);
        self
    }

    /// Approve a pending request (called by the HITL surface / approver API).
    /// Enforces independence: duplicate approvals by the same actor are
    /// idempotent no-ops.
    pub fn approve(&mut self, request_id: &str, approver_actor: &str) -> Result<(), GateError> {
        let now_ms = self.now.now_ms();
        let req = self
            .registry
            .get_mut(request_id)
            .ok_or_else(|| GateError::ApprovalRejected {
                request_id: request_id.to_string(),
                reason: "unknown request".into(),
            })?;
        if req.status == RequestStatus::Expired || now_ms >= req.expiry_ms {
            req.status = RequestStatus::Expired;
            return Err(GateError::ApprovalRejected {
                request_id: req.id.clone(),
                reason: "expired".into(),
            });
        }
        match req.status {
            RequestStatus::Pending => {}
            _ => {
                return Err(GateError::ApprovalRejected {
                    request_id: req.id.clone(),
                    reason: format!("status is {:?}", req.status),
                })
            }
        }
        if req.approvals.iter().any(|a| a == approver_actor) {
            return Ok(()); // idempotent double-approve by same actor
        }
        req.approvals.push(approver_actor.to_string());
        if req.approvals.len() >= req.required_approvals {
            req.status = RequestStatus::Approved;
        }
        Ok(())
    }

    pub fn deny(&mut self, request_id: &str, reason: &str) -> Result<(), GateError> {
        let req = self
            .registry
            .get_mut(request_id)
            .ok_or_else(|| GateError::ApprovalRejected {
                request_id: request_id.to_string(),
                reason: "unknown request".into(),
            })?;
        if req.status != RequestStatus::Pending {
            return Err(GateError::ApprovalRejected {
                request_id: req.id.clone(),
                reason: format!("status is {:?}", req.status),
            });
        }
        req.status = RequestStatus::Denied;
        req.deny_reason = Some(reason.to_string());
        Ok(())
    }

    /// Attempt the action. See type-level docs for lifecycle semantics.
    pub fn invoke(
        &mut self,
        caller: &Caller,
        args: A,
        nonce: &str,
    ) -> Result<Executed<R>, GateError> {
        // 1. Allowlist enforcement (before any state mutation).
        if !self.gate.allowlist_roles.is_empty() && !self.gate.allowlist_roles.contains(&caller.role)
        {
            return Err(GateError::RoleNotAllowed {
                role: caller.role.clone(),
                allowlist: self.gate.allowlist_roles.clone(),
            });
        }

        let base_key = (self.idempotency_key)(&args);
        let full_key = format!("{base_key}#{nonce}");
        let invocation = Invocation {
            args,
            nonce: nonce.to_string(),
        };

        // 2. Existing request under this exact key?
        if let Some(existing) = self.registry.get_by_idempotency_key(&full_key).cloned() {
            return self.resolve_existing(existing, &invocation);
        }

        // 3. Fresh attempt.
        let policy = self.gate.policy;
        if policy.required_approvals() == 0 {
            // AUTONOMOUS: execute directly.
            let result = (self.raw)(&invocation)?;
            return Ok(Executed {
                result,
                request_id: String::new(),
                autonomous: true,
            });
        }

        let now_ms = self.now.now_ms();
        let request = ApprovalRequest {
            id: (self.id_factory)(),
            gate_id: self.gate.id.clone(),
            idempotency_key: full_key,
            risk_score: self.gate.risk_score,
            policy,
            required_approvals: self.gate.required_approvals,
            approvals: vec![],
            deny_reason: None,
            status: RequestStatus::Pending,
            created_at_ms: now_ms,
            expiry_ms: now_ms + self.gate.expiry_ms,
        };
        let stored = self.registry.insert(request);
        Err(GateError::ApprovalRequired(stored))
    }

    fn resolve_existing(
        &mut self,
        existing: ApprovalRequest,
        invocation: &Invocation<A>,
    ) -> Result<Executed<R>, GateError> {
        let now_ms = self.now.now_ms();
        match existing.status {
            RequestStatus::Executed => Err(GateError::AlreadyExecuted {
                request_id: existing.id,
            }),
            RequestStatus::Denied => Err(GateError::ApprovalRejected {
                request_id: existing.id,
                reason: existing.deny_reason.unwrap_or_else(|| "denied".into()),
            }),
            RequestStatus::Expired => Err(GateError::ApprovalRejected {
                request_id: existing.id,
                reason: "expired".into(),
            }),
            RequestStatus::Pending if now_ms >= existing.expiry_ms => {
                if let Some(req) = self.registry.get_mut(&existing.id) {
                    req.status = RequestStatus::Expired;
                }
                Err(GateError::ApprovalRejected {
                    request_id: existing.id,
                    reason: "expired".into(),
                })
            }
            RequestStatus::Pending => Err(GateError::ApprovalRequired(existing)),
            RequestStatus::Approved => {
                let result = (self.raw)(invocation)?;
                if let Some(req) = self.registry.get_mut(&existing.id) {
                    req.status = RequestStatus::Executed;
                }
                Ok(Executed {
                    result,
                    request_id: existing.id,
                    autonomous: false,
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Agent v2 orchestration glue
// ---------------------------------------------------------------------------

/// Outcome reported back to the agent loop after one pipeline step — mirrors
/// the `{status: 'success' | 'pending_approval' | ...}` returns of
/// `CustomerSupportAgent.handleCustomerRefundRequest`.
#[derive(Clone, Debug, PartialEq)]
pub enum StepOutcome<R> {
    Success { request_id: String, result: R },
    PendingApproval { request_id: String, message: String },
    Rejected { request_id: String, reason: String },
    RoleDenied { role: String },
    AlreadyExecuted { request_id: String },
}

/// Drive one gated invocation and translate pipeline errors into the
/// agent-loop outcome vocabulary. The agent yields control on
/// `PendingApproval` instead of throwing — fix #4: notification failures are
/// the caller's concern, the `request_id` is always returned.
pub fn run_step<A, R, Reg, Raw, KeyFn>(
    action: &mut GatedAction<A, R, Reg, Raw, KeyFn>,
    caller: &Caller,
    args: A,
    nonce: &str,
) -> StepOutcome<R>
where
    Reg: Registry,
    Raw: Fn(&Invocation<A>) -> Result<R, GateError>,
    KeyFn: Fn(&A) -> String,
{
    match action.invoke(caller, args, nonce) {
        Ok(exec) => StepOutcome::Success {
            request_id: exec.request_id,
            result: exec.result,
        },
        Err(GateError::ApprovalRequired(req)) => StepOutcome::PendingApproval {
            request_id: req.id.clone(),
            message: format!(
                "requires {} approvals (risk {}, tier {})",
                req.required_approvals, req.risk_score, req.policy,
            ),
        },
        Err(GateError::ApprovalRejected { request_id, reason }) => {
            StepOutcome::Rejected { request_id, reason }
        }
        Err(GateError::RoleNotAllowed { role, .. }) => StepOutcome::RoleDenied { role },
        Err(GateError::AlreadyExecuted { request_id }) => {
            StepOutcome::AlreadyExecuted { request_id }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (parity with approval_gate/risk.py, pinned refund case)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    #[test]
    fn policy_bands_match_python_table_inclusive_lower_bound() {
        // Mirrors tests/test_risk_thresholds.py parametrization.
        let cases = [
            (0.0, ApprovalPolicy::Autonomous),
            (19.0, ApprovalPolicy::Autonomous),
            (20.0, ApprovalPolicy::SingleApproval),
            (39.0, ApprovalPolicy::SingleApproval),
            (40.0, ApprovalPolicy::SeniorApproval),
            (59.0, ApprovalPolicy::SeniorApproval),
            (60.0, ApprovalPolicy::DualApproval),
            (79.0, ApprovalPolicy::DualApproval),
            (80.0, ApprovalPolicy::Restricted),
            (100.0, ApprovalPolicy::Restricted),
        ];
        for (score, expected) in cases {
            assert_eq!(determine_policy(score), expected, "score {score}");
        }
    }

    #[test]
    fn refund_composite_score_pinned_to_dual_approval() {
        // Exact profile from src/actions/financial/refund.ts:
        // 25 + 20 + 15 + 0 + 5 + 5 + 0 = 70 -> DUAL_APPROVAL.
        let profile = RiskProfile {
            action_risk: 25.0,
            asset_criticality: 20.0,
            blast_radius: 15.0,
            privilege_escalation: 0.0,
            model_confidence_penalty: 5.0,
            reversibility: 5.0,
            anomaly_multiplier: 0.0,
        };
        assert_eq!(profile.composite(), 70.0);
        assert_eq!(
            determine_policy(profile.composite()),
            ApprovalPolicy::DualApproval
        );
        assert_eq!(determine_policy(70.0).as_str(), "dual_approval");
    }

    #[test]
    fn clamp_out_of_range_scores() {
        assert_eq!(clamp_score(-10.0), 0.0);
        assert_eq!(clamp_score(110.0), 100.0);
        assert_eq!(clamp_score(37.5), 37.5);
        assert_eq!(determine_policy(1_000_000.0), ApprovalPolicy::Restricted);
        assert_eq!(determine_policy(-5.0), ApprovalPolicy::Autonomous);
    }

    #[test]
    fn floors_only_escalate() {
        // authz floor lifts 30 -> 60 (DUAL_APPROVAL)
        let opts = OverrideOptions {
            affects_authz: true,
            ..Default::default()
        };
        let lifted = apply_overrides(30.0, &opts);
        assert_eq!(lifted, 60.0);
        assert_eq!(determine_policy(lifted), ApprovalPolicy::DualApproval);

        // authz floor never lowers a higher score
        assert_eq!(apply_overrides(85.0, &opts), 85.0);

        // gate modification forces RESTRICTED
        let gate_opts = OverrideOptions {
            modifies_approval_gate: true,
            ..Default::default()
        };
        assert_eq!(apply_overrides(10.0, &gate_opts), 100.0);
        assert_eq!(
            determine_policy(apply_overrides(10.0, &gate_opts)),
            ApprovalPolicy::Restricted
        );
    }

    #[test]
    fn overrides_best_matching_rule_wins() {
        let mut table: HashMap<String, OverrideRule> = HashMap::new();
        table.insert("low".into(), (0.0, 25.0));
        table.insert("high".into(), (50.0, 90.0));
        let opts = OverrideOptions {
            overrides: Some(&table),
            ..Default::default()
        };
        // score 10 only matches "low"
        assert_eq!(apply_overrides(10.0, &opts), 25.0);
        // score 60 matches both; most specific (highest bound) wins
        assert_eq!(apply_overrides(60.0, &opts), 90.0);
    }

    #[test]
    fn record_policy_matches_determine_policy() {
        let rec = create_approval_record(
            70.0,
            "financial.issue_stripe_refund",
            "agent:v2",
            None,
            None,
            None,
        );
        assert_eq!(rec.risk_score, 70.0);
        assert_eq!(rec.approval_policy, "dual_approval");
        let clamped_rec = create_approval_record(150.0, "op", "actor", None, None, None);
        assert_eq!(clamped_rec.risk_score, 100.0);
        assert_eq!(clamped_rec.approval_policy, "restricted");
    }

    // ---- pipeline lifecycle ------------------------------------------------

    #[derive(Clone, Debug)]
    struct RefundArgs {
        payment_intent_id: String,
        amount_cents: i64,
    }

    fn refund_gate() -> Gate {
        define_gate(
            "financial.issue_stripe_refund",
            "Issue Stripe Refund",
            "Processes a financial refund to a customer via Stripe.",
            RiskProfile {
                action_risk: 25.0,
                asset_criticality: 20.0,
                blast_radius: 15.0,
                privilege_escalation: 0.0,
                model_confidence_penalty: 5.0,
                reversibility: 5.0,
                anomaly_multiplier: 0.0,
            },
        )
        .required_approvals(2)
        .allowlist(&["finance_admin", "support_lead"])
        .expiry_ms(15 * 60 * 1000)
        .build()
    }

    thread_local! {
        static REQ_COUNTER: RefCell<u32> = const { RefCell::new(0) };
    }

    fn build_pipeline(
        clock: std::rc::Rc<std::cell::Cell<u64>>,
    ) -> GatedAction<
        RefundArgs,
        String,
        InMemoryRegistry,
        fn(&Invocation<RefundArgs>) -> Result<String, GateError>,
        fn(&RefundArgs) -> String,
    > {
        fn raw_refund(inv: &Invocation<RefundArgs>) -> Result<String, GateError> {
            Ok(format!(
                "re_{}_{}",
                inv.args.payment_intent_id, inv.args.amount_cents
            ))
        }
        fn key(args: &RefundArgs) -> String {
            format!("refund_{}_{}", args.payment_intent_id, args.amount_cents)
        }
        let gate = refund_gate();
        GatedAction::new(
            gate,
            InMemoryRegistry::default(),
            raw_refund as fn(&Invocation<RefundArgs>) -> Result<String, GateError>,
            key as fn(&RefundArgs) -> String,
            move || clock.get(),
        )
        .with_id_factory(|| {
            REQ_COUNTER.with(|n| {
                let v = *n.borrow();
                *n.borrow_mut() += 1;
                format!("req-{v}")
            })
        })
    }

    #[test]
    fn dual_approval_lifecycle_pending_approve_execute_block_rerun() {
        let clock = std::rc::Rc::new(std::cell::Cell::new(1_000_000u64));
        let mut pipeline = build_pipeline(Rc::clone(&clock));
        let caller = Caller {
            actor: "agent-v2".into(),
            role: "support_lead".into(),
        };
        let args = RefundArgs {
            payment_intent_id: "pi_x".into(),
            amount_cents: 5000,
        };

        // First attempt -> ApprovalRequired with score 70 / DUAL_APPROVAL.
        let err = pipeline.invoke(&caller, args.clone(), "n1").unwrap_err();
        let req = match err {
            GateError::ApprovalRequired(r) => r,
            e => panic!("expected ApprovalRequired, got {e:?}"),
        };
        assert_eq!(req.risk_score, 70.0);
        assert_eq!(req.policy, ApprovalPolicy::DualApproval);
        assert_eq!(req.required_approvals, 2);

        // Second attempt with same nonce -> still pending, no duplicate.
        let err2 = pipeline.invoke(&caller, args.clone(), "n1").unwrap_err();
        match err2 {
            GateError::ApprovalRequired(r) => assert_eq!(r.id, req.id),
            e => panic!("expected same pending request, got {e:?}"),
        }

        // Two independent approvals.
        pipeline.approve(&req.id, "finance_admin_1").unwrap();
        pipeline.approve(&req.id, "finance_admin_1").unwrap(); // idempotent
        pipeline.approve(&req.id, "support_lead_2").unwrap();

        // Execute succeeds; re-run with same key is blocked.
        let done = pipeline.invoke(&caller, args.clone(), "n1").unwrap();
        assert_eq!(done.result, "re_pi_x_5000");
        let rerun = pipeline.invoke(&caller, args.clone(), "n1").unwrap_err();
        assert!(matches!(rerun, GateError::AlreadyExecuted { .. }));

        // Retry after terminal states uses a fresh nonce -> fresh request id.
        let err3 = pipeline.invoke(&caller, args.clone(), "n2").unwrap_err();
        match err3 {
            GateError::ApprovalRequired(r) => assert_ne!(r.id, req.id),
            e => panic!("fresh nonce should create fresh request, got {e:?}"),
        }
    }

    #[test]
    fn denial_is_terminal() {
        let clock = std::rc::Rc::new(std::cell::Cell::new(1_000_000u64));
        let mut pipeline = build_pipeline(Rc::clone(&clock));
        let caller = Caller {
            actor: "a".into(),
            role: "finance_admin".into(),
        };
        let args = RefundArgs {
            payment_intent_id: "pi_d".into(),
            amount_cents: 10,
        };
        let req = match pipeline.invoke(&caller, args.clone(), "n1").unwrap_err() {
            GateError::ApprovalRequired(r) => r,
            e => panic!("{e:?}"),
        };
        pipeline.deny(&req.id, "amount mismatch").unwrap();
        let err = pipeline.invoke(&caller, args.clone(), "n1").unwrap_err();
        match err {
            GateError::ApprovalRejected { reason, .. } => assert_eq!(reason, "amount mismatch"),
            e => panic!("expected terminal rejection, got {e:?}"),
        }
    }

    #[test]
    fn expiry_is_terminal_and_role_allowlist_enforced() {
        let clock = std::rc::Rc::new(std::cell::Cell::new(1_000_000u64));
        let mut pipeline = build_pipeline(Rc::clone(&clock));
        let caller = Caller {
            actor: "a".into(),
            role: "support_lead".into(),
        };
        let args = RefundArgs {
            payment_intent_id: "pi_y".into(),
            amount_cents: 100,
        };

        let req = match pipeline.invoke(&caller, args.clone(), "n1").unwrap_err() {
            GateError::ApprovalRequired(r) => r,
            e => panic!("{e:?}"),
        };
        // Advance past expiry.
        clock.set(1_000_000 + 15 * 60 * 1000 + 1);
        let err = pipeline.invoke(&caller, args.clone(), "n1").unwrap_err();
        assert!(matches!(err, GateError::ApprovalRejected { .. }), "{err:?}");
        // Approving an expired request fails too.
        let err = pipeline.approve(&req.id, "x").unwrap_err();
        assert!(matches!(err, GateError::ApprovalRejected { .. }), "{err:?}");

        // Wrong role never reaches the registry.
        let outsider = Caller {
            actor: "b".into(),
            role: "intern".into(),
        };
        let err = pipeline.invoke(&outsider, args.clone(), "n9").unwrap_err();
        assert!(matches!(err, GateError::RoleNotAllowed { .. }), "{err:?}");
    }

    #[test]
    fn autonomous_band_executes_immediately() {
        let clock = std::rc::Rc::new(std::cell::Cell::new(0u64));
        let low_gate = define_gate(
            "read.only_lookup",
            "Lookup",
            "Non-mutating read.",
            RiskProfile {
                action_risk: 5.0,
                ..Default::default()
            },
        )
        .build();
        assert_eq!(low_gate.policy, ApprovalPolicy::Autonomous);
        let mut pipeline: GatedAction<
            RefundArgs,
            String,
            InMemoryRegistry,
            fn(&Invocation<RefundArgs>) -> Result<String, GateError>,
            fn(&RefundArgs) -> String,
        > = GatedAction::new(
            low_gate,
            InMemoryRegistry::default(),
            |inv| Ok(format!("ok-{}", inv.args.amount_cents)),
            |args| format!("lookup_{}", args.payment_intent_id),
            move || clock.get(),
        );
        let caller = Caller {
            actor: "agent-v2".into(),
            role: "anyone".into(),
        };
        let out = pipeline
            .invoke(
                &caller,
                RefundArgs {
                    payment_intent_id: "pi_a".into(),
                    amount_cents: 1,
                },
                "n1",
            )
            .unwrap();
        assert!(out.autonomous);
        assert_eq!(out.result, "ok-1");
    }

    #[test]
    fn run_step_maps_outcomes_for_agent_loop() {
        let clock = std::rc::Rc::new(std::cell::Cell::new(0u64));
        let mut pipeline = build_pipeline(Rc::clone(&clock));
        let caller = Caller {
            actor: "agent-v2".into(),
            role: "finance_admin".into(),
        };
        let args = RefundArgs {
            payment_intent_id: "pi_z".into(),
            amount_cents: 250,
        };
        let out = run_step(&mut pipeline, &caller, args.clone(), "n1");
        match out {
            StepOutcome::PendingApproval {
                request_id,
                message,
            } => {
                assert!(!request_id.is_empty());
                assert!(message.contains("tier dual_approval"), "{message}");
                pipeline.approve(&request_id, "ap1").unwrap();
                pipeline.approve(&request_id, "ap2").unwrap();
            }
            o => panic!("expected pending, got {o:?}"),
        }
        let out2 = run_step(&mut pipeline, &caller, args, "n1");
        assert!(matches!(out2, StepOutcome::Success { .. }), "{out2:?}");
    }
}
