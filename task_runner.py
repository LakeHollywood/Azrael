#!/usr/bin/env python3
"""Agent / task separation for the HITL control plane.

Before this module, long-lived processes (the NOAA telemetry agent, the
ledger API server) mixed two distinct responsibilities:

  * the **agent** — identity, configuration, lifecycle (startup/shutdown),
    health, and supervision signals; it owns *who* runs and *whether* it is
    allowed to run at all;
  * the **task** — a single unit of bounded work (fetch one feed, admit one
    transaction, verify one chain); it owns *what* happens and must be
    retryable, timeout-bounded, and auditable in isolation.

This module makes that boundary explicit and mechanical:

  ``TaskCapability``  closed vocabulary of side-effect classes a task may
                      require (e.g. FINANCIAL_MUTATION = gated money movement).
  ``TaskContext``     immutable, serializable capability grant handed to a
                      task at dispatch — the ONLY thing that crosses the
                      agent/task boundary besides plain kwargs. A context
                      lacking a required capability cannot execute the task
                      even when it runs inside a fully privileged agent.
  ``Task``            immutable specification of one unit of work, executed
                      with a wall-clock timeout and exponential retries.
  ``TaskResult``      structured outcome (status/output/error/attempts/
                      duration) — never raises into the agent loop.
  ``Agent``           named runner bound to an audit logger; holds a role
                      set and its own default TaskContext, registers tasks,
                      executes them through policy checks, records
                      every state transition in the hash-chained audit log,
                      and supervises its own liveness (heartbeat + optional
                      systemd ``WATCHDOG=1`` ping).
  ``AgentRegistry``   process-wide directory so supervisors/health endpoints
                      can enumerate agents without touching their internals.

Execution-context isolation (the strict boundary):

  * An agent's authority is the intersection of two independently checked
    layers: the agent's role set (admission) and the dispatched
    :class:`TaskContext`'s capability grant (execution). Neither alone is
    sufficient for a gated action.
  * Read-only isolation: build a read-only view with
    ``agent.context(grant=())`` (or ``TaskContext.read_only(tenant=...)``)
    and pass it via ``run_task(..., context=ctx)``. A READ_ONLY agent can
    run ``verify-chain`` but its context is refused before any gated
    financial action (``admit-transaction``) body ever runs — audited as
    ``task.rejected`` with error_type ``InsufficientCapabilities``.
  * Capability narrowing only: an explicit context must be a subset of the
    agent's own grant (delegation can never escalate); contexts are deep
    copies of caller-supplied containers, so task bodies cannot mutate the
    agent's default grant.

Design rules enforced here:

  * Fail-closed: an unregistered task name, a disabled agent, a context
    missing a required capability, or a task raising ``PermissionError``/
    ``ApprovalRequired`` refuses execution and is audited as such.
  * Audit trail: agents emit ``agent.*`` and ``task.*`` events through
    :mod:`audit_log`, correlated via ``task_id``/``agent_id`` in the record
    details, so any operator can reconstruct which agent ran which task,
    when, how many attempts, and with what outcome.
  * Isolation: task failures cannot corrupt agent state; the agent keeps a
    bounded failure window and transitions ``healthy -> degraded -> failed``
    on its own, independent of individual task results.
"""

from __future__ import annotations

import copy
import datetime
import enum
import functools
import inspect
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, Iterable, Optional

try:  # first-party, same repo root
    import audit_log
except ImportError:  # pragma: no cover - exercised only under odd sys.paths
    audit_log = None


GENESIS_STAMP = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# --------------------------------------------------------------------------
# Statuses
# --------------------------------------------------------------------------


class TaskStatus(str, enum.Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    REJECTED = "rejected"          # policy refused before execution
    SKIPPED = "skipped"            # e.g. agent not running

    @property
    def ok(self) -> bool:
        return self is TaskStatus.SUCCEEDED


class AgentState(str, enum.Enum):
    NEW = "new"
    RUNNING = "running"
    DEGRADED = "degraded"
    FAILED = "failed"
    STOPPED = "stopped"


class ApprovalRequired(Exception):
    """Raised by a task's gate or body when human approval is missing.

    The agent converts this into a REJECTED TaskResult — it is a policy
    outcome, not a crash, and it is always audited.
    """


# --------------------------------------------------------------------------
# Execution contexts (agent/task isolation boundary)
# --------------------------------------------------------------------------


class TaskCapability(str, enum.Enum):
    """Closed vocabulary of side-effect classes a task may require.

    Names describe *effects*, never specific endpoints, so the same grant
    governs any future gated action. FINANCIAL_MUTATION is the gated money
    movement class (transaction admission/execution); everything else is
    observation or local computation.
    """

    READ = "read"                          # read shared/local state
    NETWORK_READ = "network_read"          # fetch remote data (GET-style)
    AUDIT_WRITE = "audit_write"            # append audit records
    LEDGER_VERIFY = "ledger_verify"        # recompute hashes / walk chains
    TELEMETRY_INGEST = "telemetry_ingest"  # bind telemetry into local state
    FINANCIAL_MUTATION = "financial_mutation"  # GATED: moves money
    APPROVAL_GRANT = "approval_grant"      # clear an approval gate (human/HITL)


#: Capabilities that mark an action as gated/high-blast-radius. A context
#: lacking one of these can NEVER execute a task requiring it, even inside
#: a fully privileged agent — this is what makes a read-only execution
#: context unable to invoke a gated financial action.
GATED_CAPABILITIES: FrozenSet["TaskCapability"] = frozenset(
    {TaskCapability.FINANCIAL_MUTATION, TaskCapability.APPROVAL_GRANT}
)


class TaskMode(str, enum.Enum):
    """Execution-context class of an agent (or of a dispatched context)."""

    READ_ONLY = "read_only"    # observation only; no gated actions possible
    WORKER = "worker"          # domain side effects (ingest, verify, ...)
    PRIVILEGED = "privileged"  # may carry gated capabilities


def _coerce_caps(values: Iterable[Any], field_name: str) -> FrozenSet[TaskCapability]:
    out = set()
    for v in values or ():
        if isinstance(v, TaskCapability):
            out.add(v)
        elif isinstance(v, str):
            try:
                out.add(TaskCapability(v))
            except ValueError:
                raise ValueError(
                    f"unknown capability {v!r} in {field_name}; "
                    f"valid: {[c.value for c in TaskCapability]}"
                ) from None
        else:
            raise TypeError(f"{field_name} entries must be TaskCapability or str")
    return frozenset(out)


@dataclass(frozen=True)
class TaskContext:
    """Immutable capability grant handed to a task at dispatch time.

    This is the strict context-passing mechanism across the agent/task
    boundary: the context declares exactly which side-effect classes the
    invocation may perform, plus non-secret scoping attributes (tenant,
    actor). It is deliberately serializable (``as_dict``) so it can cross
    process boundaries later without smuggling live objects.

    Invariants enforced here:
      * ``gated_capabilities`` ⊆ ``capabilities`` (a grant cannot claim a
        gated cap without actually holding it);
      * mode READ_ONLY ⇒ empty grant; mode PRIVILEGED ⇔ non-empty
        ``gated_capabilities`` intersection with GATED_CAPABILITIES;
      * caller-supplied containers are deep-copied on construction, so a
        task body can never mutate the agent's default context through
        references captured before the frozen snapshot.
    """

    capabilities: FrozenSet[TaskCapability] = frozenset({TaskCapability.READ})
    gated_capabilities: FrozenSet[TaskCapability] = frozenset()
    tenant: Optional[str] = None
    actor: Optional[str] = None
    mode: TaskMode = TaskMode.WORKER
    metadata: Dict[str, Any] = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        caps = _coerce_caps(self.capabilities, "capabilities")
        gated = _coerce_caps(self.gated_capabilities, "gated_capabilities")
        object.__setattr__(self, "capabilities", caps)
        object.__setattr__(self, "gated_capabilities", gated)
        object.__setattr__(self, "metadata",
                           copy.deepcopy(dict(self.metadata or {})))
        if not isinstance(self.mode, TaskMode):
            self._check_mode(TaskMode(str(self.mode)))
        else:
            self._check_mode(self.mode)
        if not gated <= caps:
            raise ValueError(
                "gated_capabilities must be a subset of capabilities "
                f"(missing: {sorted(c.value for c in gated - caps)})"
            )

    def _check_mode(self, mode: TaskMode) -> None:
        object.__setattr__(self, "mode", mode)
        has_gated = bool(self.gated_capabilities & GATED_CAPABILITIES)
        if mode is TaskMode.READ_ONLY and self.capabilities:
            raise ValueError("READ_ONLY context must have an empty grant")
        if mode is TaskMode.PRIVILEGED and not has_gated:
            raise ValueError("PRIVILEGED context must hold a gated capability")
        if mode is TaskMode.WORKER and has_gated:
            raise ValueError(
                "WORKER context cannot hold gated capabilities; use "
                "TaskMode.PRIVILEGED (explicitly) instead"
            )

    # -- constructors ----------------------------------------------------

    @classmethod
    def read_only(cls, *, tenant: Optional[str] = None,
                  actor: Optional[str] = None,
                  metadata: Optional[Dict[str, Any]] = None) -> "TaskContext":
        """A context that can observe but never mutate or move money."""
        return cls(capabilities=frozenset(), gated_capabilities=frozenset(),
                   tenant=tenant, actor=actor, mode=TaskMode.READ_ONLY,
                   metadata=metadata)

    @classmethod
    def privileged(cls, *, gated=(TaskCapability.FINANCIAL_MUTATION,),
                   extra=(TaskCapability.READ, TaskCapability.AUDIT_WRITE),
                   tenant: Optional[str] = None, actor: Optional[str] = None,
                   metadata: Optional[Dict[str, Any]] = None) -> "TaskContext":
        """A context carrying gated capabilities (money movement etc.)."""
        gated = _coerce_caps(gated, "gated")
        caps = _coerce_caps(extra, "extra") | gated
        return cls(capabilities=caps, gated_capabilities=gated,
                   tenant=tenant, actor=actor, mode=TaskMode.PRIVILEGED,
                   metadata=metadata)

    @classmethod
    def derive(cls, base_capabilities: Iterable[Any], *,
               tenant: Optional[str] = None, actor: Optional[str] = None,
               metadata: Optional[Dict[str, Any]] = None) -> "TaskContext":
        """Build a context whose mode is *inferred* from its grant.

        This is the safe way to narrow an existing grant (e.g. strip gated
        capabilities for a read-only dispatch view): PRIVILEGED iff any
        gated capability remains, WORKER otherwise, READ_ONLY for an empty
        grant. Unlike direct construction it cannot desynchronise mode and
        capabilities.
        """
        caps = _coerce_caps(base_capabilities, "base_capabilities")
        gated = caps & GATED_CAPABILITIES
        if not caps:
            mode = TaskMode.READ_ONLY
        elif gated:
            mode = TaskMode.PRIVILEGED
        else:
            mode = TaskMode.WORKER
        return cls(capabilities=caps, gated_capabilities=gated, tenant=tenant,
                   actor=actor, mode=mode, metadata=metadata)

    # -- queries -----------------------------------------------------------

    def can(self, cap: Any) -> bool:
        return _coerce_caps([cap], "cap") <= self.capabilities

    def requires_all(self, caps: Iterable[TaskCapability]) -> FrozenSet[TaskCapability]:
        """Capabilities in ``caps`` this context does NOT hold (empty ⇒ OK)."""
        return _coerce_caps(caps, "required") - self.capabilities

    def narrowed(self, **changes: Any) -> "TaskContext":
        """Derive a sub-context; grants may only shrink, never grow.

        When the capability set changes, the mode is re-derived from the
        resulting grant (see :meth:`derive`) so narrowing a PRIVILEGED
        context down to non-gated caps yields a valid WORKER context
        instead of a contradictory one.
        """
        base = self.as_kwargs()
        base.update(changes)
        caps = _coerce_caps(base["capabilities"], "capabilities")
        if not caps <= self.capabilities:
            raise ValueError("narrowed context cannot add capabilities")
        gated = _coerce_caps(base.get("gated_capabilities") or (), "gated")
        if not gated <= caps:
            raise ValueError("cannot gate capabilities the context does not hold")
        if self.tenant is not None and base.get("tenant") not in (None, self.tenant):
            raise ValueError("narrowed context cannot switch tenants")
        return TaskContext.derive(caps | gated, tenant=base.get("tenant"),
                                  actor=base.get("actor"),
                                  metadata=base.get("metadata"))

    def as_kwargs(self) -> Dict[str, Any]:
        return {
            "capabilities": self.capabilities,
            "gated_capabilities": self.gated_capabilities,
            "tenant": self.tenant,
            "actor": self.actor,
            "mode": self.mode,
            "metadata": dict(self.metadata),
        }

    def as_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "capabilities": sorted(c.value for c in self.capabilities),
            "gated_capabilities": sorted(c.value for c in self.gated_capabilities),
            "tenant": self.tenant,
            "actor": self.actor,
        }


class InsufficientCapabilities(PermissionError):
    """Raised internally when a dispatched context lacks a required grant.

    Because it subclasses PermissionError, existing fail-closed handling in
    ``Agent.run_task`` maps it to a REJECTED TaskResult (never retried,
    always audited) with no special-casing elsewhere.
    """

    def __init__(self, missing: Iterable[TaskCapability], task_name: str) -> None:
        names = sorted(c.value for c in missing)
        super().__init__(
            f"context lacks required capabilities {names} for task {task_name!r}"
        )
        self.missing = tuple(missing)
        self.task_name = task_name


def enforce_context(task: "Task", context: TaskContext) -> None:
    """Fail closed if ``context`` cannot legally execute ``task``.

    Checked BEFORE the task's own gate runs: capability isolation is
    structural, not advisory — a read-only context never reaches gated task
    code, its gate, or its body.
    """
    missing = context.requires_all(task.requires)
    if missing:
        raise InsufficientCapabilities(missing, task.name)


# --------------------------------------------------------------------------
# Tasks
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TaskPolicy:
    """Execution bounds owned by the task spec, not the caller."""

    timeout_seconds: float = 30.0
    max_attempts: int = 1
    retry_backoff_seconds: float = 0.5
    retry_on: tuple = (Exception,)  # which exceptions are retried

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be > 0")
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if self.retry_backoff_seconds < 0:
            raise ValueError("retry_backoff_seconds must be >= 0")


@dataclass(frozen=True)
class TaskResult:
    task_name: str
    task_id: str
    agent_id: Optional[str]
    status: TaskStatus
    output: Any = None
    error: Optional[str] = None
    error_type: Optional[str] = None
    attempts: int = 0
    started_at: str = GENESIS_STAMP.isoformat()
    finished_at: str = GENESIS_STAMP.isoformat()
    duration_ms: float = 0.0
    context_mode: Optional[str] = None
    required_capabilities: tuple = ()

    @property
    def ok(self) -> bool:
        return self.status.ok

    def as_dict(self) -> Dict[str, Any]:
        return {
            "task_name": self.task_name,
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "status": self.status.value,
            "error": self.error,
            "error_type": self.error_type,
            "attempts": self.attempts,
            "duration_ms": round(self.duration_ms, 3),
            "context_mode": self.context_mode,
            "required_capabilities": [
                c.value if isinstance(c, TaskCapability) else str(c)
                for c in self.required_capabilities
            ],
        }


class Task:
    """One bounded unit of work with a name, a callable, and policy.

    ``requires`` declares the :class:`TaskCapability` set the dispatching
    :class:`TaskContext` must grant before this task may execute (checked
    fail-closed by the agent *before* ``gate`` runs). Gated financial tasks
    declare FINANCIAL_MUTATION; a read-only context can therefore never
    invoke them even through a privileged agent.

    ``gate`` is an optional pre-execution check: raise :class:`ApprovalRequired`
    or ``PermissionError`` from it and the task is rejected without ever
    invoking ``run`` (fail-closed).
    """

    def __init__(
        self,
        name: str,
        run: Callable[..., Any],
        *,
        gate: Optional[Callable[["Task", Dict[str, Any]], None]] = None,
        policy: Optional[TaskPolicy] = None,
        description: str = "",
        requires: Iterable[Any] = (),
    ) -> None:
        if not name or not isinstance(name, str):
            raise ValueError("task name must be a non-empty string")
        if not callable(run):
            raise TypeError("task run must be callable")
        if gate is not None and not callable(gate):
            raise TypeError("task gate must be callable or None")
        self.name = name
        self.run = run
        self.gate = gate
        self.policy = policy or TaskPolicy()
        self.description = description
        self.requires: FrozenSet[TaskCapability] = _coerce_caps(requires, "requires")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        req = ",".join(sorted(c.value for c in self.requires)) or "-"
        return f"<Task {self.name!r} requires=[{req}] policy={self.policy!r}>"


def task(
    name: Optional[str] = None,
    *,
    gate: Optional[Callable[[Task, Dict[str, Any]], None]] = None,
    policy: Optional[TaskPolicy] = None,
    description: str = "",
    requires: Iterable[Any] = (),
) -> Callable[[Callable[..., Any]], Task]:
    """Decorator turning a function into a registered-able :class:`Task`.

    Usage::

        @task("fetch-noaa", policy=TaskPolicy(timeout_seconds=3))
        def fetch(url): ...

        @task("send-payment", requires=(TaskCapability.FINANCIAL_MUTATION,))
        def pay(ctx, amount): ...   # first positional arg receives the grant
    """

    def deco(fn: Callable[..., Any]) -> Task:
        doc = (fn.__doc__ or "").strip()
        first_line = doc.splitlines()[0] if doc else ""
        return Task(
            name or fn.__name__,
            fn,
            gate=gate,
            policy=policy,
            description=description or first_line,
            requires=requires,
        )

    return deco


def _run_with_timeout(fn: Callable[[], Any], timeout_seconds: float) -> Any:
    """Run ``fn`` on a worker thread; raise TimeoutError past the deadline.

    The abandoned thread is daemonized: a timed-out task can never hang the
    agent's main loop (its result is simply discarded).
    """
    box: Dict[str, Any] = {}
    done = threading.Event()

    def target() -> None:
        try:
            box["result"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised on caller
            box["error"] = exc
        finally:
            done.set()

    th = threading.Thread(target=target, daemon=True, name="task-worker")
    th.start()
    if not done.wait(timeout_seconds):
        raise TimeoutError(f"task exceeded {timeout_seconds:g}s timeout")
    if "error" in box:
        raise box["error"]
    return box.get("result")


# --------------------------------------------------------------------------
# Agents
# --------------------------------------------------------------------------


class Agent:
    """A named, audited runner that executes Tasks under a policy.

    The agent deliberately knows nothing about what its tasks do; it only
    enforces identity, lifecycle, liveness, and audit. This is the seam that
    lets new workloads (telemetry feeds, ledger checks) plug in without
    growing god-object daemons.
    """

    #: consecutive failures within the window before state -> DEGRADED
    degrade_after_failures: int = 2
    #: consecutive failures before state -> FAILED (and heartbeat marks dead)
    fail_after_failures: int = 4
    failure_window: int = 8  # keep this many recent results

    def __init__(
        self,
        agent_id: Optional[str] = None,
        *,
        name: Optional[str] = None,
        version: str = "0.1.0",
        roles: Iterable[str] = (),
        audit_logger: Any = None,
        registry: Optional["AgentRegistry"] = None,
        metadata: Optional[Dict[str, Any]] = None,
        mode: TaskMode = TaskMode.WORKER,
        capabilities: Iterable[Any] = (TaskCapability.READ,),
        gated_capabilities: Iterable[Any] = (),
        context: Optional[TaskContext] = None,
    ) -> None:
        self.agent_id = agent_id or f"agent-{uuid.uuid4().hex[:8]}"
        self.name = name or self.agent_id
        self.version = version
        self.roles = tuple(roles)
        self.metadata = dict(metadata or {})
        self._tasks: Dict[str, Task] = {}
        self._state = AgentState.NEW
        self._lock = threading.RLock()
        self._results: list[TaskResult] = []
        self._started_at: Optional[str] = None
        self._last_heartbeat: Optional[str] = None
        self._logger = audit_logger
        self._registry = registry
        # Default execution context: the ceiling of everything this agent may
        # dispatch. Explicit per-call contexts must narrow it, never exceed it.
        if context is not None:
            if not isinstance(context, TaskContext):
                raise TypeError("context must be a TaskContext")
            self.default_context = context
        else:
            self.default_context = TaskContext(
                capabilities=frozenset(capabilities),
                gated_capabilities=frozenset(gated_capabilities),
                mode=mode,
                metadata={"agent_id": self.agent_id},
            )
        if registry is not None:
            registry.register(self)

    @property
    def mode(self) -> TaskMode:
        return self.default_context.mode

    def context(self, **changes: Any) -> TaskContext:
        """Derive a dispatch view of this agent's authority.

        ``agent.context(grant=())`` (i.e. capabilities=frozenset()) yields a
        read-only view; any narrowing is safe, any escalation raises. The
        result is meant to be handed to ``run_task(..., context=view)``.
        """
        if "grant" in changes:
            changes.setdefault("capabilities", changes.pop("grant"))
        if changes.get("capabilities") == frozenset() or changes.get("mode") == TaskMode.READ_ONLY:
            return TaskContext.read_only(
                tenant=changes.get("tenant", self.default_context.tenant),
                actor=changes.get("actor", self.default_context.actor))
        return self.default_context.narrowed(**changes)

    # -- audit ------------------------------------------------------------

    @property
    def audit(self):
        if self._logger is None:
            if audit_log is None:  # pragma: no cover
                raise RuntimeError("audit_log module unavailable")
            self._logger = audit_log.get_logger()
        return self._logger

    def _emit(self, event_type: str, outcome: str, details: Dict[str, Any]) -> None:
        """Best-effort audit write; logging must never break task execution."""
        base = {"agent_id": self.agent_id, "agent_name": self.name}
        try:
            self.audit.log_event(
                event_type,
                actor=f"agent:{self.agent_id}",
                outcome=outcome,
                resource="agent" if event_type.startswith("agent.") else "task",
                details={**base, **details},
            )
        except Exception as exc:  # pragma: no cover - defensive
            import sys

            print(f"[{self.name}] audit write failed: {exc}", file=sys.stderr)

    # -- registration ------------------------------------------------------

    def register(self, *tasks_: Task) -> "Agent":
        with self._lock:
            for t in tasks_:
                if not isinstance(t, Task):
                    raise TypeError(f"expected Task, got {type(t).__name__}")
                if t.name in self._tasks:
                    raise ValueError(f"task {t.name!r} already registered")
                # Static consistency: a task requiring gated capabilities may
                # not be registered on an agent whose role set is explicitly
                # read-only. (The runtime defense-in-depth — dispatched
                # contexts lacking the capability — applies to EVERY agent,
                # including privileged ones.)
                if (t.requires & GATED_CAPABILITIES
                        and "READ_ONLY" in self.roles):
                    raise ValueError(
                        f"task {t.name!r} requires gated capabilities "
                        f"{sorted(c.value for c in t.requires & GATED_CAPABILITIES)} "
                        f"but agent {self.agent_id!r} is READ_ONLY"
                    )
                self._tasks[t.name] = t
        return self

    def unregister(self, name: str) -> None:
        with self._lock:
            self._tasks.pop(name, None)

    @property
    def tasks(self) -> Dict[str, Task]:
        with self._lock:
            return dict(self._tasks)

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        with self._lock:
            if self._state is AgentState.RUNNING:
                return
            self._state = AgentState.RUNNING
            self._started_at = _utc_now_iso()
            self._results.clear()
        self._emit("agent.started", "started", {"version": self.version})

    def stop(self) -> None:
        with self._lock:
            was_running = self._state in (
                AgentState.RUNNING,
                AgentState.DEGRADED,
                AgentState.FAILED,
            )
            self._state = AgentState.STOPPED
        if was_running:
            self._emit("agent.stopped", "stopped", {})

    def heartbeat(self) -> Dict[str, Any]:
        """Liveness signal; also pings the systemd watchdog when present."""
        with self._lock:
            self._last_heartbeat = _utc_now_iso()
            hb = {
                "agent_id": self.agent_id,
                "name": self.name,
                "state": self._state.value,
                "ts": self._last_heartbeat,
                "recent_failures": sum(
                    1 for r in self._results[-self.failure_window :] if not r.ok
                ),
            }
        try:  # optional sd_notify integration (no-op outside systemd)
            import sts_noaa_telemetry_agent as sts

            sts.sd_notify("WATCHDOG=1")
        except Exception:
            pass
        return hb

    @property
    def state(self) -> AgentState:
        with self._lock:
            return self._state

    def health(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "agent_id": self.agent_id,
                "name": self.name,
                "version": self.version,
                "roles": list(self.roles),
                "mode": self.default_context.mode.value,
                "context": self.default_context.as_dict(),
                "state": self._state.value,
                "started_at": self._started_at,
                "last_heartbeat": self._last_heartbeat,
                "tasks": sorted(self._tasks),
                "recent_results": [r.as_dict() for r in self._results[-self.failure_window :]],
            }

    # -- supervision ---------------------------------------------------------

    def _record_result(self, res: TaskResult) -> AgentState:
        with self._lock:
            self._results.append(res)
            del self._results[:-self.failure_window]
            recent = self._results[-self.failure_window :]
            failures = sum(1 for r in recent if not r.ok)
            previous = self._state
            if self._state in (AgentState.RUNNING, AgentState.DEGRADED):
                if failures >= self.fail_after_failures:
                    self._state = AgentState.FAILED
                elif failures >= self.degrade_after_failures:
                    self._state = AgentState.DEGRADED
                elif failures == 0:
                    self._state = AgentState.RUNNING
            if previous is not self._state:
                self._emit(
                    "agent.state_changed",
                    self._state.value,
                    {"from": previous.value, "recent_failures": failures},
                )
            return self._state

    # -- execution -----------------------------------------------------------

    def _resolve_context(self, explicit: Optional[TaskContext]) -> TaskContext:
        """Resolve the dispatch context; delegation can only narrow authority.

        * no explicit context → the agent's default grant;
        * explicit context   → must be a subset of the agent's capabilities
          (a caller can never escalate by handing in a richer context);
        * READ_ONLY agents always downgrade to an empty grant — even an
          explicitly passed privileged context cannot execute gated work
          through them (agent admission dominates).
        """
        if self.default_context.mode is TaskMode.READ_ONLY:
            return TaskContext.read_only(tenant=explicit.tenant if explicit else None,
                                         actor=explicit.actor if explicit else None)
        if explicit is None:
            return self.default_context
        if not isinstance(explicit, TaskContext):
            raise TypeError("context must be a TaskContext or None")
        extra = explicit.capabilities - self.default_context.capabilities
        if extra:
            raise InsufficientCapabilities(extra, "context-delegation")
        return explicit

    @staticmethod
    def _accepts_ctx(fn: Callable[..., Any]) -> bool:
        try:
            sig = inspect.signature(fn)
        except (ValueError, TypeError):  # pragma: no cover - exotic callables
            return False
        params = list(sig.parameters.values())
        return bool(params) and params[0].name == "ctx" and (
            params[0].kind in (params[0].POSITIONAL_ONLY,
                               params[0].POSITIONAL_OR_KEYWORD)
        )

    def run_task(
        self,
        name_or_task: Any,
        *,
        context: Optional[TaskContext] = None,
        **kwargs: Any,
    ) -> TaskResult:
        """Execute one task by name (or Task object); never raises TaskErrors.

        The dispatched :class:`TaskContext` (this agent's default, or an
        explicitly narrowed one) is enforced BEFORE the task's own gate and
        body run: if it lacks any capability the task declares in
        ``requires``, execution is refused fail-closed as REJECTED
        (error_type ``InsufficientCapabilities``) and audited — so a
        read-only context can never invoke a gated financial action, even
        when dispatched through a fully privileged agent.

        Returns a structured TaskResult. Policy rejections and crashes both
        land in the audit log with the same correlation ids.
        """
        with self._lock:
            state = self._state
            if isinstance(name_or_task, Task):
                t = self._tasks.get(name_or_task.name, name_or_task)
            else:
                t = self._tasks.get(name_or_task)
        task_id = f"task-{uuid.uuid4().hex[:10]}"

        if t is None:
            # Fail closed: unknown work is refused, loudly, and audited.
            res = TaskResult(
                task_name=str(name_or_task),
                task_id=task_id,
                agent_id=self.agent_id,
                status=TaskStatus.REJECTED,
                error=f"no task named {name_or_task!r} registered",
                error_type="UnknownTask",
            )
            self._emit("task.rejected", res.status.value, res.as_dict())
            return res

        if state not in (AgentState.RUNNING, AgentState.DEGRADED):
            res = TaskResult(
                task_name=t.name,
                task_id=task_id,
                agent_id=self.agent_id,
                status=TaskStatus.SKIPPED,
                error=f"agent is {state.value}",
                error_type="AgentNotRunning",
            )
            self._emit("task.skipped", res.status.value, res.as_dict())
            return res

        # ---- execution-context isolation (strict boundary) ----------------
        try:
            ctx = self._resolve_context(context)
            enforce_context(t, ctx)
        except (InsufficientCapabilities, ApprovalRequired, PermissionError,
                TypeError, ValueError) as exc:
            res = TaskResult(
                task_name=t.name,
                task_id=task_id,
                agent_id=self.agent_id,
                status=TaskStatus.REJECTED,
                error=str(exc),
                error_type=type(exc).__name__,
                attempts=0,
                started_at=_utc_now_iso(),
                finished_at=_utc_now_iso(),
                context_mode=(context.mode.value if context is not None
                              else self.default_context.mode.value),
                required_capabilities=t.requires,
            )
            self._emit("task.rejected", res.status.value, res.as_dict())
            self._record_result(res)
            return res

        # Context passing: bodies/gates whose first parameter is named `ctx`
        # receive the resolved grant positionally; everything else keeps the
        # plain-kwargs contract (backward compatible).
        run_kwargs = dict(kwargs)
        run_args: tuple = ()
        gate_args: tuple = ()
        if self._accepts_ctx(t.run):
            run_args = (ctx,)
        if t.gate is not None and self._accepts_ctx(t.gate):
            gate_args = (ctx,)

        self._emit("task.started", "started", {
            "task_name": t.name, "task_id": task_id,
            "input_keys": sorted(kwargs),
            "context_mode": ctx.mode.value,
            "required_capabilities": [c.value for c in sorted(t.requires, key=lambda c: c.value)],
        })
        started = time.monotonic()
        started_iso = _utc_now_iso()
        status = TaskStatus.FAILED
        output: Any = None
        error: Optional[BaseException] = None
        attempts = 0

        try:
            if t.gate is not None:
                # Gate failures are policy outcomes: caught here so they map
                # to REJECTED (never retried, never crash the agent loop).
                t.gate(*gate_args, t, run_kwargs)
        except (ApprovalRequired, PermissionError) as exc:
            duration_ms = (time.monotonic() - started) * 1000.0
            res = TaskResult(
                task_name=t.name,
                task_id=task_id,
                agent_id=self.agent_id,
                status=TaskStatus.REJECTED,
                error=str(exc),
                error_type=type(exc).__name__,
                attempts=0,
                started_at=started_iso,
                finished_at=_utc_now_iso(),
                duration_ms=duration_ms,
                context_mode=ctx.mode.value,
                required_capabilities=t.requires,
            )
            self._emit("task.rejected", res.status.value, res.as_dict())
            self._record_result(res)
            return res

        try:
            for attempt in range(1, t.policy.max_attempts + 1):
                attempts = attempt
                try:
                    output = _run_with_timeout(
                        functools.partial(t.run, *run_args, **run_kwargs),
                        t.policy.timeout_seconds,
                    )
                    status = TaskStatus.SUCCEEDED
                    error = None
                    break
                except (ApprovalRequired, PermissionError) as exc:
                    # Policy outcomes are never retried.
                    status = TaskStatus.REJECTED
                    error = exc
                    break
                except Exception as exc:
                    if not isinstance(exc, t.policy.retry_on):
                        status = TaskStatus.FAILED
                        error = exc
                        break
                    status = TaskStatus.TIMED_OUT if isinstance(exc, TimeoutError) else TaskStatus.FAILED
                    error = exc
                    if attempt < t.policy.max_attempts:
                        time.sleep(t.policy.retry_backoff_seconds * (2 ** (attempt - 1)))
        except BaseException as exc:  # pragma: no cover - last-resort guard
            status = TaskStatus.FAILED
            error = exc

        duration_ms = (time.monotonic() - started) * 1000.0
        res = TaskResult(
            task_name=t.name,
            task_id=task_id,
            agent_id=self.agent_id,
            status=status,
            output=output if status.ok else None,
            error=None if error is None else str(error),
            error_type=None if error is None else type(error).__name__,
            attempts=attempts,
            started_at=started_iso,
            finished_at=_utc_now_iso(),
            duration_ms=duration_ms,
            context_mode=ctx.mode.value,
            required_capabilities=t.requires,
        )
        self._emit(f"task.{res.status.value}", res.status.value, res.as_dict())
        self._record_result(res)
        return res

    def run_cycle(self, names: Optional[Iterable[str]] = None) -> Dict[str, TaskResult]:
        """Run each named (or all registered) task once; results keyed by name."""
        with self._lock:
            targets = list(names) if names is not None else sorted(self._tasks)
        return {n: self.run_task(n) for n in targets}


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------


class AgentRegistry:
    """Process-wide directory of agents for supervisors and health endpoints."""

    def __init__(self) -> None:
        self._agents: Dict[str, Agent] = {}
        self._lock = threading.Lock()

    def register(self, agent: Agent) -> Agent:
        with self._lock:
            existing = self._agents.get(agent.agent_id)
            if existing is not None and existing is not agent:
                raise ValueError(f"agent_id {agent.agent_id!r} already registered")
            self._agents[agent.agent_id] = agent
        return agent

    def get(self, agent_id: str) -> Optional[Agent]:
        with self._lock:
            return self._agents.get(agent_id)

    def unregister(self, agent_id: str) -> None:
        with self._lock:
            self._agents.pop(agent_id, None)

    def list_agents(self) -> list[Agent]:
        with self._lock:
            return list(self._agents.values())

    def health_all(self) -> list[Dict[str, Any]]:
        return [a.health() for a in self.list_agents()]


DEFAULT_REGISTRY = AgentRegistry()


def make_agent(*args: Any, use_default_registry: bool = True, **kwargs: Any) -> Agent:
    """Factory: build an Agent attached to the default registry."""
    if use_default_registry and "registry" not in kwargs:
        kwargs["registry"] = DEFAULT_REGISTRY
    return Agent(*args, **kwargs)


# --------------------------------------------------------------------------
# CLI smoke test
# --------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    demo = make_agent("demo-agent", roles=("smoke",))

    @task("always-ok", policy=TaskPolicy(timeout_seconds=1))
    def _ok() -> str:
        return "done"

    @task("flaky", policy=TaskPolicy(timeout_seconds=1, max_attempts=3, retry_backoff_seconds=0.01))
    def _flaky(_state: dict = {"n": 0}) -> str:
        _state["n"] += 1
        if _state["n"] < 3:
            raise RuntimeError("transient")
        return "recovered"

    demo.register(_ok, _flaky)
    demo.start()
    results = demo.run_cycle()
    demo.stop()
    for name, r in results.items():
        print(f"{name}: {r.status.value} attempts={r.attempts} err={r.error}")
