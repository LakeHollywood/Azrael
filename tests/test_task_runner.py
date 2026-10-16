"""Tests for agent/task separation (task_runner.py).

Covers the two halves of the boundary:

  * TASKS  — timeout bounds, retries, gate-based fail-closed rejection,
             structured results that never raise into the agent loop.
  * AGENTS — lifecycle states, supervision transitions
             (healthy -> degraded -> failed), registry, health snapshot,
             and hash-chained audit correlation between agent and task.
"""

import json
import os
import subprocess
import sys
import time

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import audit_log  # noqa: E402
import task_runner  # noqa: E402
from task_runner import (  # noqa: E402
    Agent,
    AgentRegistry,
    AgentState,
    ApprovalRequired,
    Task,
    TaskPolicy,
    TaskStatus,
    task,
)


@pytest.fixture()
def audit_file(tmp_path, monkeypatch):
    """Redirect the shared audit logger at a per-test JSONL file."""
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AUDIT_LOG_FILE", str(path))
    audit_log.reset_logger()
    yield path
    audit_log.reset_logger()


def read_records(path):
    if not os.path.exists(path):
        return []
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


# ---------------------------------------------------------------------------
# Task specification & policy validation
# ---------------------------------------------------------------------------


class TestTaskSpec:
    def test_task_requires_name_and_callable(self):
        with pytest.raises(ValueError):
            Task("", lambda: None)
        with pytest.raises(TypeError):
            Task("x", run="not callable")
        with pytest.raises(TypeError):
            Task("x", lambda: None, gate="not callable")

    def test_policy_bounds_validated(self):
        with pytest.raises(ValueError):
            TaskPolicy(timeout_seconds=0)
        with pytest.raises(ValueError):
            TaskPolicy(max_attempts=0)
        with pytest.raises(ValueError):
            TaskPolicy(retry_backoff_seconds=-1)

    def test_decorator_builds_task_with_docstring_description(self):
        @task("demo", policy=TaskPolicy(timeout_seconds=2))
        def demo():
            """Do the demo thing.

            Extra lines ignored.
            """

        assert isinstance(demo, Task)
        assert demo.name == "demo"
        assert demo.description == "Do the demo thing."
        assert demo.policy.timeout_seconds == 2

    def test_duplicate_registration_rejected(self):
        agent = Agent("dup-agent", audit_logger=audit_log.AuditLogger())
        agent.register(Task("a", lambda: None))
        with pytest.raises(ValueError):
            agent.register(Task("a", lambda: None))


# ---------------------------------------------------------------------------
# Execution semantics: success, failure, retry, timeout
# ---------------------------------------------------------------------------


class TestExecution:
    def _agent(self, audit_file):
        agent = Agent("exec-agent", audit_logger=audit_log.get_logger())
        agent.start()
        return agent

    def test_success_returns_output(self, audit_file):
        agent = self._agent(audit_file)
        agent.register(Task("ok", lambda: {"answer": 42}))
        res = agent.run_task("ok")
        assert res.status is TaskStatus.SUCCEEDED
        assert res.ok and res.attempts == 1
        assert res.output == {"answer": 42}
        assert res.duration_ms >= 0

    def test_failure_is_structured_not_raised(self, audit_file):
        def boom():
            raise ValueError("kaput")

        agent = self._agent(audit_file)
        agent.register(Task("boom", boom))
        res = agent.run_task("boom")  # must not raise
        assert res.status is TaskStatus.FAILED
        assert res.error == "kaput"
        assert res.error_type == "ValueError"
        assert res.output is None

    def test_retries_with_backoff_until_success(self, audit_file):
        state = {"n": 0}

        def flaky():
            state["n"] += 1
            if state["n"] < 3:
                raise RuntimeError("transient")
            return "recovered"

        agent = self._agent(audit_file)
        agent.register(Task(
            "flaky", flaky,
            policy=TaskPolicy(max_attempts=5, retry_backoff_seconds=0.001),
        ))
        res = agent.run_task("flaky")
        assert res.status is TaskStatus.SUCCEEDED
        assert res.attempts == 3
        assert res.output == "recovered"

    def test_non_retryable_exception_stops_immediately(self, audit_file):
        calls = {"n": 0}

        def deny():
            calls["n"] += 1
            raise PermissionError("nope")

        agent = self._agent(audit_file)
        # retry_on excludes PermissionError via narrower tuple
        agent.register(Task(
            "deny", deny,
            policy=TaskPolicy(max_attempts=4, retry_backoff_seconds=0.001,
                              retry_on=(RuntimeError,)),
        ))
        res = agent.run_task("deny")
        assert res.status is TaskStatus.REJECTED  # policy outcome, not retried
        assert calls["n"] == 1

    def test_timeout_marks_timed_out(self, audit_file):
        def slow():
            time.sleep(2)
            return "late"

        agent = self._agent(audit_file)
        agent.register(Task("slow", slow,
                            policy=TaskPolicy(timeout_seconds=0.05)))
        start = time.monotonic()
        res = agent.run_task("slow")
        elapsed = time.monotonic() - start
        assert res.status is TaskStatus.TIMED_OUT
        assert "timeout" in res.error.lower()
        assert elapsed < 1.0  # bounded by the deadline, not the sleep

    def test_unknown_task_fails_closed(self, audit_file):
        agent = self._agent(audit_file)
        res = agent.run_task("does-not-exist")
        assert res.status is TaskStatus.REJECTED
        assert res.error_type == "UnknownTask"

    def test_stopped_agent_skips_tasks(self, audit_file):
        agent = self._agent(audit_file)
        agent.register(Task("ok", lambda: 1))
        agent.stop()
        res = agent.run_task("ok")
        assert res.status is TaskStatus.SKIPPED
        assert res.error_type == "AgentNotRunning"

    def test_new_agent_also_skips(self, audit_file):
        agent = Agent("never-started", audit_logger=audit_log.get_logger())
        agent.register(Task("ok", lambda: 1))
        assert agent.run_task("ok").status is TaskStatus.SKIPPED


# ---------------------------------------------------------------------------
# Gates: pre-execution policy checks
# ---------------------------------------------------------------------------


class TestGates:
    def test_gate_rejection_never_runs_body(self, audit_file):
        ran = {"n": 0}

        def body():
            ran["n"] += 1
            return "should not happen"

        def gate(t, kwargs):
            raise ApprovalRequired("missing human approval")

        agent = Agent("gate-agent", audit_logger=audit_log.get_logger())
        agent.start()
        agent.register(Task("guarded", body, gate=gate))
        res = agent.run_task("guarded", x=1)
        assert res.status is TaskStatus.REJECTED
        assert ran["n"] == 0
        assert "approval" in res.error

    def test_gate_pass_allows_execution(self, audit_file):
        agent = Agent("gate-ok", audit_logger=audit_log.get_logger())
        agent.start()
        agent.register(Task("guarded", lambda v: v * 2,
                            gate=lambda t, kw: None))
        res = agent.run_task("guarded", v=21)
        assert res.ok and res.output == 42


# ---------------------------------------------------------------------------
# Supervision: state transitions driven by failure windows
# ---------------------------------------------------------------------------


class TestSupervision:
    def _agent(self, audit_file):
        return Agent("sup-agent", audit_logger=audit_log.get_logger())

    def test_degrade_then_fail_then_recover(self, audit_file):
        agent = self._agent(audit_file)
        agent.start()
        agent.register(Task("bad", lambda: (_ for _ in ()).throw(RuntimeError("x"))))
        agent.register(Task("good", lambda: "fine"))

        assert agent.state is AgentState.RUNNING
        agent.run_task("bad")                       # 1 failure: still healthy
        assert agent.state is AgentState.RUNNING
        agent.run_task("bad")                       # 2 failures: degraded
        assert agent.state is AgentState.DEGRADED
        agent.run_task("bad")
        agent.run_task("bad")                       # 4 consecutive: failed
        assert agent.state is AgentState.FAILED
        # FAILED agents refuse new work...
        assert agent.run_task("good").status is TaskStatus.SKIPPED
        # ...until an operator restarts them.
        agent.start()
        assert agent.state is AgentState.RUNNING
        assert agent.run_task("good").ok

    def test_state_changes_are_audited(self, audit_file):
        agent = self._agent(audit_file)
        agent.start()
        agent.register(Task("bad", lambda: 1 / 0))
        for _ in range(agent.degrade_after_failures):
            agent.run_task("bad")
        events = [r["event_type"] for r in read_records(audit_file)]
        assert "agent.started" in events
        assert "agent.state_changed" in events
        changed = [r for r in read_records(audit_file)
                   if r["event_type"] == "agent.state_changed"][0]
        assert changed["details"]["from"] == "running"
        assert changed["outcome"] == "degraded"


# ---------------------------------------------------------------------------
# Audit trail: correlation between agents and tasks
# ---------------------------------------------------------------------------


class TestAuditTrail:
    def test_full_lifecycle_emits_correlated_chain(self, audit_file):
        agent = Agent("audit-agent", name="Auditor",
                      audit_logger=audit_log.get_logger())
        agent.register(Task("work", lambda: "done"))
        agent.start()
        res = agent.run_task("work")
        agent.stop()

        records = read_records(audit_file)
        events = [r["event_type"] for r in records]
        assert events[:1] == ["agent.started"]
        assert "task.started" in events
        assert "task.succeeded" in events
        assert "agent.stopped" in events

        # every record carries the agent identity and belongs to the chain
        for r in records:
            assert r["details"]["agent_id"] == "audit-agent"
        ok, errs = audit_log.verify_chain(str(audit_file))
        assert ok, errs

        # task records share one task_id so started/outcome pair up
        started = next(r for r in records if r["event_type"] == "task.started")
        done = next(r for r in records if r["event_type"] == "task.succeeded")
        assert started["details"]["task_id"] == done["details"]["task_id"] == res.task_id
        assert done["actor"] == "agent:audit-agent"

    def test_audit_write_failure_does_not_break_execution(self, audit_file, monkeypatch):
        agent = Agent("resilient", audit_logger=audit_log.get_logger())
        agent.start()
        agent.register(Task("ok", lambda: "still runs"))

        class Broken:
            def log_event(self, *a, **k):
                raise OSError("disk on fire")

        agent._logger = Broken()
        res = agent.run_task("ok")
        assert res.ok  # logging is best-effort; work continues


# ---------------------------------------------------------------------------
# Registry & health surface
# ---------------------------------------------------------------------------


class TestRegistryAndHealth:
    def test_registry_directory(self):
        reg = AgentRegistry()
        a1 = Agent("a1", registry=reg)
        a2 = Agent("a2", registry=reg)
        assert {a.agent_id for a in reg.list_agents()} == {"a1", "a2"}
        assert reg.get("a1") is a1
        with pytest.raises(ValueError):
            Agent("a1-id-clash", registry=reg)
            reg.register(Agent("a1"))  # different object, same id
        reg.unregister("a1")
        assert reg.get("a1") is None

    def test_health_snapshot_shape(self):
        agent = Agent("h-agent", name="H", version="1.2.3",
                      roles=("telemetry",), audit_logger=audit_log.AuditLogger())
        agent.register(Task("t1", lambda: None), Task("t2", lambda: None))
        agent.start()
        agent.run_task("t1")
        hb = agent.heartbeat()
        h = agent.health()
        assert h["state"] == "running"
        assert h["tasks"] == ["t1", "t2"]
        assert h["version"] == "1.2.3"
        assert len(h["recent_results"]) == 1
        assert h["recent_results"][0]["task_name"] == "t1"
        assert hb["state"] == "running"
        assert hb["recent_failures"] == 0

    def test_run_cycle_covers_all_tasks(self):
        agent = Agent("cycle", audit_logger=audit_log.AuditLogger())
        agent.register(Task("b", lambda: 2), Task("a", lambda: 1))
        agent.start()
        results = agent.run_cycle()
        assert set(results) == {"a", "b"}
        assert all(r.ok for r in results.values())
        partial = agent.run_cycle(["a"])
        assert set(partial) == {"a"}


# ---------------------------------------------------------------------------
# Integration with the real agents in this repo
# ---------------------------------------------------------------------------


class TestRepoIntegration:
    def test_telemetry_agent_builds_with_feed_tasks(self):
        sts = pytest.importorskip("sts_noaa_telemetry_agent")
        agent = sts.build_agent("test-telemetry")
        assert agent.name == "STS NOAA Telemetry Agent"
        assert set(agent.tasks) == {f"ingest:{n}" for n in sts.NOAA_ENDPOINTS}
        for t in agent.tasks.values():
            # each feed poll is timeout-bounded so a hung feed can't stall
            assert t.policy.timeout_seconds <= 10
        # unstarted agent refuses work (fail closed) — no network touched
        res = agent.run_task("ingest:GOES_MAG")
        assert res.status is TaskStatus.SKIPPED

    def test_ledger_api_admits_through_task_boundary(self, tmp_path, monkeypatch):
        monkeypatch.chdir(REPO_ROOT)
        env = dict(os.environ, AUDIT_LOG_FILE=str(tmp_path / "audit.jsonl"),
                   LEDGER_API_PORT="0")
        proc = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, 'scripts');"
             "import ledger_api_server as api;"
             "a = api.LedgerAPI();"
             "print(a.health()['state']);"
             "print(sorted(a.agent.tasks));"
             "s, p = a.post_transaction('bogus-tenant', {});"
             "print(s, p.get('error'));"],
            capture_output=True, text=True, timeout=60, env=env, cwd=REPO_ROOT,
        )
        assert proc.returncode == 0, proc.stderr
        lines = proc.stdout.splitlines()
        assert lines[0] == "running"
        assert "admit-transaction" in lines[1]
        # unknown tenant refused by the gate before any task code ran
        assert "404 unknown_tenant" in lines[2]
        records = read_records(tmp_path / "audit.jsonl")
        events = [r["event_type"] for r in records]
        assert "agent.started" in events
        assert "task.rejected" in events

    def test_module_cli_smoke(self):
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "task_runner.py")],
            capture_output=True, text=True, timeout=60,
            env=dict(os.environ, AUDIT_LOG_FILE="/tmp/tr-smoke-audit.jsonl"),
        )
        assert proc.returncode == 0, proc.stderr
        assert "always-ok: succeeded" in proc.stdout
        assert "flaky: succeeded attempts=3" in proc.stdout
