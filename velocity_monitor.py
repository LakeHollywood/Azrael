"""Rolling-window velocity control for autonomous agents.

A ``VelocityMonitor`` caps how fast an agent may act inside a sliding time
window, using two independent limits evaluated together:

  * ``action_count_limit``   -- max number of autonomous actions in the window
  * ``autonomous_risk_limit`` -- max cumulative risk score in the window

State lives in a Redis sorted set per agent: members are unique action ids
(fixed-width hex microsecond timestamp + random suffix, so simultaneous
actions never collide) and scores are the action's risk contribution.
Expired entries are pruned with ``ZREMRANGEBYLEX`` on the encoded timestamp
prefix before evaluation (scores hold risk, not time), and the key gets a
TTL just past the window so idle agents eventually release their memory.

Result strings:
  WITHIN_LIMITS    -> action recorded, caller may proceed autonomously
  VELOCITY_EXCEEDED-> either limit would be breached, action NOT recorded
"""

from __future__ import annotations

import time
import uuid

# Atomic check+record script (see VelocityMonitor.check_and_record_atomic).
# Module-level constant so it is built once at import and registered with the
# Redis server via SCRIPT LOAD / EVALSHA instead of shipping the body per call.
_ATOMIC_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local risk = tonumber(ARGV[3])
local risk_limit = tonumber(ARGV[4])
local count_limit = tonumber(ARGV[5])
local member = ARGV[6]
local cutoff = ARGV[7]

-- Scores hold risk, so expiry is lexicographic on the hex-ts member prefix.
redis.call('ZREMRANGEBYLEX', key, '-', '(' .. cutoff)
local count = redis.call('ZCARD', key)
local total = 0
local entries = redis.call('ZRANGE', key, 0, -1, 'WITHSCORES')
for i = 2, #entries, 2 do
  total = total + tonumber(entries[i])
end
if count >= count_limit or (total + risk) > risk_limit then
  return 0
end
redis.call('ZADD', key, risk, member)
redis.call('EXPIRE', key, window + 1)
return 1
"""


class VelocityMonitor:
    # Result constants.
    WITHIN_LIMITS = "WITHIN_LIMITS"
    VELOCITY_EXCEEDED = "VELOCITY_EXCEEDED"

    def __init__(self, redis_client, *, time_fn=None):
        self.redis = redis_client
        self.window_seconds = 900  # 15-minute rolling window
        self.autonomous_risk_limit = 100  # Max cumulative risk score allowed autonomously
        self.action_count_limit = 50  # Max autonomous actions allowed in window
        # Injectable clock (deterministic tests).
        self._time_fn = time_fn or time.time

    def _key(self, agent_id):
        return f"velocity:{agent_id}"

    def _prune(self, key, now):
        """Drop entries that have slid out of the window.

        Entries are scored by risk (not timestamp), so expiry is done by
        member: each member encodes its action time as a fixed-width hex
        prefix (``"%016x" % (ts * 1e6)``) followed by a sequence number, and
        ZREMRANGEBYLEX removes every member whose encoded timestamp is
        below the cutoff. Fixed-width lowercase hex sorts lexicographically
        in exactly numeric order.
        """
        cutoff = self._encode_ts(now - self.window_seconds)
        # "(<cutoff>" is exclusive at the cutoff string; members carry extra
        # suffix bytes but compare first on the 16-char ts field, so any
        # member with ts < cutoff sorts below it and is removed.
        self.redis.zremrangebylex(key, "-", f"({cutoff}")

    @staticmethod
    def _encode_ts(ts):
        return "%016x" % int(ts * 1_000_000)

    @classmethod
    def _member(cls, now):
        # Fixed-width hex ts (microseconds) + random suffix for uniqueness.
        return f"{cls._encode_ts(now)}:{uuid.uuid4().hex}"

    def get_window_stats(self, agent_id):
        """Return ``(action_count, cumulative_risk)`` for the current window.

        Single pipeline round-trip (ZCARD + ZRANGE WITHSCORES are batched);
        the score sum walks only the score elements of the flat reply that
        redis-py returns for ``zrange(..., withscores=True)``.
        """
        now = self._time_fn()
        key = self._key(agent_id)
        self._prune(key, now)
        # One pipelined round-trip instead of two sequential ones.
        pipe = self.redis.pipeline() if hasattr(self.redis, "pipeline") else None
        if pipe is not None:
            pipe.zcard(key)
            pipe.zrange(key, 0, -1, withscores=True)
            action_count, scored = pipe.execute()
        else:  # minimal fake/test client without pipeline support
            action_count = self.redis.zcard(key)
            scored = self.redis.zrange(key, 0, -1, withscores=True)
        # scored is a list of (member, score) pairs -- sum element [1] only.
        cumulative_risk = float(sum(float(s) for _m, s in scored))
        return int(action_count), cumulative_risk

    def check_velocity(self, agent_id, next_action_risk_score):
        """Evaluate the next action and record it if within limits.

        Returns WITHIN_LIMITS (action recorded) or VELOCITY_EXCEEDED (not
        recorded). Note this is a check-then-record sequence: under truly
        concurrent callers use :meth:`check_and_record_atomic` instead.

        Performance: the admit path costs exactly TWO Redis round-trips —
        one pipelined prune+read, and (only when admitted) one pipelined
        record+expire. The previous implementation issued four to five
        separate round-trips per action (prune, zcard, zrange, zadd, expire).
        """
        now = self._time_fn()
        risk = float(next_action_risk_score)
        key = self._key(agent_id)
        cutoff = f"({self._encode_ts(now - self.window_seconds)}"

        # 1+2. Prune expired entries, then read window stats — batched into
        #      one round-trip. Pipeline order guarantees ZREMRANGEBYLEX runs
        #      server-side before the reads (FIFO within the connection).
        if hasattr(self.redis, "pipeline"):
            pipe = self.redis.pipeline(transaction=False)
            pipe.zremrangebylex(key, "-", cutoff)
            pipe.zcard(key)
            pipe.zrange(key, 0, -1, withscores=True)
            _, action_count, scored = pipe.execute()
        else:  # minimal fake/test client without pipeline support
            self._prune(key, now)
            action_count = self.redis.zcard(key)
            scored = self.redis.zrange(key, 0, -1, withscores=True)

        # 3. Evaluate against limits (strictly-greater keeps "max N allowed").
        cumulative_risk = float(sum(float(s) for _m, s in scored))
        if int(action_count) >= self.action_count_limit or (cumulative_risk + risk) > self.autonomous_risk_limit:
            return self.VELOCITY_EXCEEDED

        # 4. Record the new action in the window. Member = fixed-width hex
        #    timestamp (microseconds) + random suffix, so simultaneous
        #    actions never overwrite each other and lexicographic pruning
        #    works on the encoded time. ZADD + EXPIRE batched in one
        #    round-trip; the key lives just past the window so idle agents
        #    eventually release their memory.
        member = self._member(now)
        if hasattr(self.redis, "pipeline"):
            pipe = self.redis.pipeline(transaction=False)
            pipe.zadd(key, {member: risk})
            pipe.expire(key, int(self.window_seconds) + 1)
            pipe.execute()
        else:
            self.redis.zadd(key, {member: risk})
            self.redis.expire(key, int(self.window_seconds) + 1)
        return self.WITHIN_LIMITS

    def check_and_record_atomic(self, agent_id, next_action_risk_score):
        """Lua-scripted check+record to avoid the read-modify-write race.

        Falls back to :meth:`check_velocity` when the client cannot run
        scripts (e.g. a fake/test client).

        Performance: the Lua body is a module constant registered once per
        client and cached on the instance, so every subsequent admission is a
        single EVALSHA round-trip instead of rebuilding/hashing the script
        string and shipping its full body on every call.
        """
        register = getattr(self.redis, "register_script", None)
        if register is None:
            return self.check_velocity(agent_id, next_action_risk_score)

        # Cache the compiled Script object per client (attribute lookup via
        # object.__getattribute__ keeps this cheap; assignment is atomic
        # enough for our purposes — worst case the script is registered twice).
        run_script = getattr(self, "_atomic_script", None)
        if run_script is None or getattr(self, "_atomic_script_client", None) \
                is not self.redis:
            run_script = register(_ATOMIC_LUA)
            self._atomic_script = run_script
            self._atomic_script_client = self.redis

        now = self._time_fn()
        member = self._member(now)
        try:
            ok = run_script(
                [self._key(agent_id)],  # KEYS
                [                        # ARGV (redis-py Script signature: keys, *args)
                    now,
                    self.window_seconds,
                    float(next_action_risk_score),
                    self.autonomous_risk_limit,
                    self.action_count_limit,
                    member,
                    self._encode_ts(now - self.window_seconds),
                ],
            )
        except Exception:
            # Server (or fake) without Lua support -> non-atomic fallback.
            return self.check_velocity(agent_id, next_action_risk_score)
        return self.WITHIN_LIMITS if int(ok) == 1 else self.VELOCITY_EXCEEDED

    def reset(self, agent_id):
        """Clear all recorded actions for an agent."""
        self.redis.delete(self._key(agent_id))
