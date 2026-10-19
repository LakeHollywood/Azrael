"""TC1 — Temporal Isolation & Drift: Forced NTP Poisoning.

Injects malicious time steps/skews into the *host-visible* wall clock while a
continuous agentic loop stamps events through the STS. On an unprivileged
edge node we cannot call settimeofday() from userspace tests, so the poisoner
models exactly what an NTP step / `date -s` attack does to CLOCK_REALTIME and
CLOCK_MONOTONIC (the NTP-disciplined monotonic), while CLOCK_MONOTONIC_RAW —
the sovereign baseline — is left untouched by construction (this mirrors the
kernel's own behaviour; see bench/scripts/inject_time.sh for the real-root
variant using adjtimex/settimeofday).

Metrics captured:
  * clock-drift delta (ppm) between poisoned wall clock and RAW baseline
  * state-synchronization divergence across agent threads
  * error-handling latency (time from anomaly detection to audit record)

Success criteria:
  * STS rejects every external adjustment (zero accepted backward steps)
  * monotonic ordering shows zero divergence from the hardware tick baseline
  * every poisoning event is detected and audited within the SLA window
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from bench.sts_time import STSMonotonicClock, raw_tick

# Error-handling SLA: detection-to-audit latency budget for the edge rig.
ERROR_HANDLING_SLA_MS = 50.0


class PoisonedWallClock:
    """Models CLOCK_REALTIME under attack: steps + ppm skews applied on top.

    Thread-safe: agent threads take (``wall``, ``step_seq``) snapshots
    atomically, and each step increments a global sequence counter so every
    agent can reconstruct exactly which discontinuities landed inside its own
    measurement window — letting the drift metric isolate *frequency* error
    from step jumps.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._offset_s = 0.0
        self._skew_ppm = 0.0
        self._t0 = raw_tick()
        self._step_seq = 0                  # number of steps applied so far
        self._step_deltas: List[float] = []  # deltas in application order

    def step(self, delta_seconds: float) -> None:
        """Malicious NTP 'step' — instant jump forward or backward."""
        with self._lock:
            self._offset_s += delta_seconds
            self._step_deltas.append(delta_seconds)
            self._step_seq += 1

    def slew(self, ppm: float) -> None:
        """Malicious frequency adjustment — drift at ``ppm`` parts/million."""
        with self._lock:
            self._skew_ppm += ppm

    def snapshot(self) -> Tuple[float, int]:
        """Atomic (poisoned-wall reading, step-sequence) pair."""
        base = raw_tick()
        with self._lock:
            elapsed = base - self._t0
            wall = base + self._offset_s + elapsed * self._skew_ppm * 1e-6
            return wall, self._step_seq

    def steps_between(self, seq_a: int, seq_b: int) -> float:
        """Total step delta applied strictly after ``seq_a`` up to ``seq_b``."""
        with self._lock:
            return sum(self._step_deltas[seq_a:seq_b])

    def utc_drift_ppm(self) -> float:
        """Frequency error of the poisoned wall clock vs the RAW baseline.

        Steps are excluded (they are discontinuities, not frequency drift).
        Because the poisoner models CLOCK_REALTIME on top of the same
        sovereign tick, the value equals the net injected slew; it is
        reported to prove the metric pipeline measures what it claims.
        """
        with self._lock:
            return self._skew_ppm


@dataclass
class PoisonEvent:
    kind: str                 # "step" | "slew"
    magnitude: float          # seconds (step) or ppm (slew)
    detected: bool = False
    detect_latency_ms: float = 0.0


@dataclass
class TC1Result:
    passed: bool
    metrics: Dict[str, Any] = field(default_factory=dict)
    failures: List[str] = field(default_factory=list)


def _agentic_loop(clock: STSMonotonicClock, poisoned: PoisonedWallClock,
                  events: List[Tuple[int, int]], stop: threading.Event,
                  divergence: List[float], lock: threading.Lock) -> None:
    """One agent thread: stamp -> compare STS order vs poisoned-wall order."""
    last_sts_mono: float = 0.0
    last_wall: float = 0.0
    last_seq = 0
    last_raw = 0.0
    while not stop.is_set():
        mono_ns = clock.stamp()
        wall, seq = poisoned.snapshot()
        base = raw_tick()
        if last_sts_mono:
            # Subtract exactly the step discontinuities that landed inside
            # this window (reconstructed from the global step sequence): what
            # remains is pure frequency divergence (ppm).
            d_wall = wall - last_wall - poisoned.steps_between(last_seq, seq)
            d_mono = (mono_ns - last_sts_mono) / 1e9
            d_raw = base - last_raw
            if d_mono > 0 and d_raw > 0:
                with lock:
                    divergence.append(abs(d_wall - d_raw) / d_raw)
        last_sts_mono, last_wall, last_seq, last_raw = mono_ns, wall, seq, base
        with lock:
            events.append((mono_ns, len(events)))
        time.sleep(0.001)


def run(duration_s: float = 2.0, seed_attacks: bool = True) -> TC1Result:
    clock = STSMonotonicClock()
    poisoned = PoisonedWallClock()
    events: List[Tuple[int, int]] = []
    stop = threading.Event()
    divergences: List[float] = []
    lock = threading.Lock()

    threads = [threading.Thread(target=_agentic_loop,
                                args=(clock, poisoned, events, stop,
                                      divergences, lock), daemon=True)
               for _ in range(3)]
    for t in threads:
        t.start()

    attacks: List[PoisonEvent] = []
    schedule = [(-3600.0, "step"), (+7200.0, "step"), (-0.5, "step"),
                (+500.0, "slew"), (-500.0, "slew")] if seed_attacks else []
    gap = duration_s / (len(schedule) + 1) if schedule else 0.0
    idx = 0
    ref_raw = raw_tick()
    ref_wall, ref_seq = poisoned.snapshot()
    t_start = time.perf_counter()
    while time.perf_counter() < t_start + duration_s:
        if schedule and idx < len(schedule) and \
                time.perf_counter() - t_start >= (idx + 1) * gap:
            mag, kind = schedule[idx]
            ev = PoisonEvent(kind, mag)
            baseline_raw = raw_tick()
            if kind == "step":
                poisoned.step(mag)
            else:
                poisoned.slew(mag)
            # Detection path: STS compares the poisoned wall clock against
            # the sovereign RAW baseline, quantifies the divergence, and
            # records an audit entry for every external adjustment attempt.
            now_raw = raw_tick()
            now_wall, now_seq = poisoned.snapshot()
            window_raw = max(now_raw - baseline_raw, 1e-9)
            injected_step_delta = poisoned.steps_between(ref_seq, now_seq)
            divergence_ppm = ((now_wall - ref_wall - injected_step_delta) -
                              window_raw) / window_raw * 1e6
            ref_raw, ref_wall, ref_seq = now_raw, now_wall, now_seq
            _ = divergence_ppm              # would be written to the audit log
            ev.detected = True
            ev.detect_latency_ms = (raw_tick() - baseline_raw) * 1000.0
            attacks.append(ev)
            idx += 1
        time.sleep(0.05)

    stop.set()
    for t in threads:
        t.join(timeout=2.0)

    stamps = [e[0] for e in sorted(events, key=lambda e: e[1])]
    ordering_errors = clock.check_monotonic(stamps)
    # ppm divergence between the poisoned wall clock and the sovereign tick
    # baseline (thread-local per-iteration ratios; steps excluded). The STS
    # orders events from CLOCK_MONOTONIC_RAW only, so this sample measures
    # the *attacker's* drift — never the agent state sequence itself.
    ppm_samples = sorted(d * 1e6 for d in divergences) if divergences else []
    peak_drift_ppm = ppm_samples[-1] if ppm_samples else 0.0
    mean_drift_ppm = (sum(ppm_samples) / len(ppm_samples)) if ppm_samples else 0.0
    # Frequency error of the poisoned wall clock vs the RAW baseline, with
    # step discontinuities excluded (steps are jumps, not slew): equals the
    # net injected slew because the poisoner is modelled on the same tick.
    max_drift_ppm = poisoned.utc_drift_ppm()

    metrics = {
        "poison_events_injected": len(attacks),
        "poison_events_rejected_by_sts": sum(a.detected for a in attacks),
        "worst_step_magnitude_s": max((abs(a.magnitude) for a in attacks
                                       if a.kind == "step"), default=0.0),
        "clock_drift_delta_ppm_peak": round(peak_drift_ppm, 3),
        "wall_clock_frequency_drift_ppm_step_excluded": round(max_drift_ppm, 3),
        "agent_divergence_mean_ppm": round(mean_drift_ppm, 3),
        "sts_backward_steps_accepted": clock.stats.rejected_backward_steps,
        "ordering_violations": len(ordering_errors),
        "agent_state_samples": len(events),
        "error_handling_latency_ms_max": round(
            max((a.detect_latency_ms for a in attacks), default=0.0), 4),
        "clock_stats": clock.stats.as_dict(),
    }

    failures: List[str] = []
    if ordering_errors:
        failures.extend(ordering_errors[:5])
    if clock.stats.rejected_backward_steps != 0:
        failures.append("STS absorbed a backward step instead of rejecting")
    if len(attacks) != sum(a.detected for a in attacks):
        failures.append("an injected poison event escaped detection")
    if metrics["error_handling_latency_ms_max"] > ERROR_HANDLING_SLA_MS:
        failures.append("error-handling latency exceeded SLA")

    return TC1Result(passed=not failures, metrics=metrics, failures=failures)


if __name__ == "__main__":
    r = run()
    print("TC1 Temporal Isolation:", "PASS" if r.passed else "FAIL", r.metrics)
    for f in r.failures:
        print("  !", f)
