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

  ``Task``            immutable specification of one unit of work, executed
                      with a wall-clock timeout and exponential retries.
  ``TaskResult``      structured outcome (status/output/error/attempts/
                      duration) — never raises into the agent loop.
  ``Agent``           named runner bound to an audit logger; registers
                      tasks, executes them through policy checks, records
                      every state transition in the hash-chained audit log,
                      and supervises its own liveness (heartbeat + optional
                      systemd ``WATCHDOG=1`` ping).
  ``AgentRegistry``   process-wide directory so supervisors/health endpoints
                      can enumerate agents without touching their internals.

Design rules enforced here:

  * Fail-closed: an unregistered task name, a disabled agent, or a task
    raising ``PermissionError``/``ApprovalRequired`` refuses execution and
    is audited as such.
  * Audit trail: agents emit ``agent.*`` and ``task.*`` events through
    :mod:`audit_log`, correlated via ``task_id``/``agent_id`` in the record
    details, so any operator can reconstruct which agent ran which task,
    when, how many attempts, and with what outcome.
  * Isolation: task failures cannot corrupt agent state; the agent keeps a
    bounded failure window and transitions ``healthy -> degraded -> failed``
    on its own, independent of individual task results.
"""

from __future__ import annotations

import datetime
import enum
import functools
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Optional

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
        }


class Task:
    """One bounded unit of work with a name, a callable, and policy.

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

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Task {self.name!r} policy={self.policy!r}>"


def task(
    name: Optional[str] = None,
    *,
    gate: Optional[Callable[[Task, Dict[str, Any]], None]] = None,
    policy: Optional[TaskPolicy] = None,
    description: str = "",
) -> Callable[[Callable[..., Any]], Task]:
    """Decorator turning a function into a registered-able :class:`Task`.

    Usage::

        @task("fetch-noaa", policy=TaskPolicy(timeout_seconds=3))
        def fetch(url): ...
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
        if registry is not None:
            registry.register(self)

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

    def run_task(self, name_or_task: Any, **kwargs: Any) -> TaskResult:
        """Execute one task by name (or Task object); never raises TaskErrors.

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

        self._emit("task.started", "started", {"task_name": t.name, "task_id": task_id, "input_keys": sorted(kwargs)})
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
                t.gate(t, kwargs)
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
            )
            self._emit("task.rejected", res.status.value, res.as_dict())
            self._record_result(res)
            return res

        try:
            for attempt in range(1, t.policy.max_attempts + 1):
                attempts = attempt
                try:
                    output = _run_with_timeout(
                        functools.partial(t.run, **kwargs),
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
