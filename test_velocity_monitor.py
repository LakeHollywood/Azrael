"""Tests for velocity_monitor.VelocityMonitor using an in-memory Redis fake."""

import pytest

from velocity_monitor import VelocityMonitor


class FakeRedis:
    """Minimal sorted-set fake matching redis-py semantics used here."""

    def __init__(self):
        self.zsets = {}  # key -> {member: score}
        self.ttls = {}

    def zadd(self, key, mapping):
        zset = self.zsets.setdefault(key, {})
        added = 0
        for member, score in mapping.items():
            if member not in zset:
                added += 1
            zset[member] = float(score)
        return added

    def zcard(self, key):
        return len(self.zsets.get(key, {}))

    def zrange(self, key, start, stop, withscores=False):
        items = sorted(self.zsets.get(key, {}).items(), key=lambda kv: (kv[1], kv[0]))
        n = len(items)
        if stop == -1:
            end = n
        else:
            end = stop + 1
        selected = items[start:end]
        if withscores:
            return [(m, s) for m, s in selected]
        return [m for m, _ in selected]

    def zremrangebyscore(self, key, min_score, max_score):
        zset = self.zsets.get(key, {})
        lo = -float("inf") if min_score == "-inf" else float(min_score)
        hi = float("inf") if max_score == "+inf" else float(max_score)
        doomed = [m for m, s in zset.items() if lo <= s <= hi]
        for m in doomed:
            del zset[m]
        return len(doomed)

    def zremrangebylex(self, key, min_lex, max_lex):
        """Redis ZREMRANGEBYLEX semantics for the ranges used here."""
        assert min_lex == "-", f"unsupported min spec {min_lex!r}"
        assert max_lex.startswith("("), f"unsupported max spec {max_lex!r}"
        bound = max_lex[1:]
        zset = self.zsets.get(key, {})
        doomed = [m for m in zset if m < bound]
        for m in doomed:
            del zset[m]
        return len(doomed)

    def expire(self, key, seconds):
        self.ttls[key] = seconds

    def delete(self, key):
        self.zsets.pop(key, None)
        self.ttls.pop(key, None)


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def make_monitor(clock=None):
    clock = clock or Clock()
    r = FakeRedis()
    m = VelocityMonitor(r, time_fn=clock)
    return m, r, clock


def test_first_action_within_limits():
    m, r, _ = make_monitor()
    assert m.check_velocity("agent-1", 10) == "WITHIN_LIMITS"
    assert r.zcard("velocity:agent-1") == 1


def test_risk_limit_enforced_cumulative():
    m, _, _ = make_monitor()
    for _ in range(10):
        assert m.check_velocity("agent-1", 10) == "WITHIN_LIMITS"
    # 10*10 = 100 cumulative; an 11th risk-10 action would hit 110 > 100.
    assert m.check_velocity("agent-1", 10) == "VELOCITY_EXCEEDED"


def test_risk_limit_boundary_exact_is_allowed():
    m, _, _ = make_monitor()
    for _ in range(9):
        m.check_velocity("agent-1", 10)
    # 90 + 10 == 100, not > 100 -> allowed ("max cumulative 100").
    assert m.check_velocity("agent-1", 10) == "WITHIN_LIMITS"


def test_action_count_limit_enforced():
    m, _, _ = make_monitor()
    for i in range(50):
        assert m.check_velocity("agent-2", 0.1) == "WITHIN_LIMITS"
    assert m.check_velocity("agent-2", 0.1) == "VELOCITY_EXCEEDED"


def test_sliding_window_expiry_restores_headroom():
    clock = Clock()
    m, r, clock = make_monitor(clock)
    for _ in range(10):
        m.check_velocity("agent-3", 10)
    assert m.check_velocity("agent-3", 1) == "VELOCITY_EXCEEDED"
    clock.advance(m.window_seconds + 1)  # everything slides out
    count, total = m.get_window_stats("agent-3")
    assert (count, total) == (0, 0.0)
    assert m.check_velocity("agent-3", 10) == "WITHIN_LIMITS"


def test_partial_window_expiry_only_drops_old_entries():
    clock = Clock()
    m, r, clock = make_monitor(clock)
    m.check_velocity("agent-4", 60)  # old, risk 60
    clock.advance(600)               # 10 min later
    m.check_velocity("agent-4", 30)  # recent, risk 30
    clock.advance(400)               # old entry now 1000s stale (>900)
    count, total = m.get_window_stats("agent-4")
    assert count == 1
    assert total == 30  # the buggy tuple-sum would have crashed/garbage'd here


def test_same_timestamp_actions_do_not_collide():
    clock = Clock()
    m, r, clock = make_monitor(clock)
    for _ in range(5):
        assert m.check_velocity("agent-5", 1) == "WITHIN_LIMITS"  # clock frozen
    assert r.zcard("velocity:agent-5") == 5
    _, total = m.get_window_stats("agent-5")
    assert total == 5.0


def test_exceeded_action_is_not_recorded():
    m, r, _ = make_monitor()
    for _ in range(10):
        m.check_velocity("agent-6", 10)
    before = r.zcard("velocity:agent-6")
    assert m.check_velocity("agent-6", 50) == "VELOCITY_EXCEEDED"
    assert r.zcard("velocity:agent-6") == before


def test_agents_are_isolated():
    m, _, _ = make_monitor()
    for _ in range(10):
        m.check_velocity("agent-A", 10)
    assert m.check_velocity("agent-B", 10) == "WITHIN_LIMITS"


def test_key_ttl_set_to_window():
    clock = Clock()
    m, r, clock = make_monitor(clock)
    m.check_velocity("agent-7", 1)
    assert r.ttls["velocity:agent-7"] == m.window_seconds + 1


def test_reset_clears_state():
    m, r, _ = make_monitor()
    m.check_velocity("agent-8", 50)
    m.reset("agent-8")
    assert r.zcard("velocity:agent-8") == 0
    assert m.check_velocity("agent-8", 50) == "WITHIN_LIMITS"


def test_atomic_path_falls_back_without_register_script():
    m, _, _ = make_monitor()
    assert not hasattr(FakeRedis, "register_script")
    # Falls back to check_velocity transparently.
    assert m.check_and_record_atomic("agent-9", 10) == "WITHIN_LIMITS"


def test_zero_and_negative_scores_clamped_by_membership():
    m, r, _ = make_monitor()
    assert m.check_velocity("agent-10", 0) == "WITHIN_LIMITS"
    assert m.get_window_stats("agent-10")[1] == 0.0


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
