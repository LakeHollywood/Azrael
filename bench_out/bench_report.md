# STS Edge-Agentic Validation — Benchmark Report

Generated: 2026-10-19 22:55:45 UTC

| Category | Phase | Result | Key metrics |
|---|---|---|---|
| 1. Temporal Isolation & Drift | Baseline | ✅ PASS | poison_events_injected=0, poison_events_rejected_by_sts=0, worst_step_magnitude_s=0.0, clock_drift_delta_ppm_peak=81894.881 |
| 2. High-Frequency Jitter | Baseline | ✅ PASS | loader_threads=2, agent_threads=3, ledger_rows=86, backward_time_jumps=0 |
| 3. Ledger Throughput & SEAL Integrity | Baseline | ✅ PASS | rows_committed=6500, sustained_tps=6669.4, burst_tps=16781.2, burst_ratio_vs_sustained=2.516 |
| 4. Adversarial Network Attacks | Baseline | ✅ PASS | cycles_attempted=60, cycles_delivered=11, cycles_degraded_locally_buffered=49, heartbeat_survival_ratio=2.52 |
| 1. Temporal Isolation & Drift | Stress | ✅ PASS | poison_events_injected=5, poison_events_rejected_by_sts=5, worst_step_magnitude_s=7200.0, clock_drift_delta_ppm_peak=1156468.41 |
| 2. High-Frequency Jitter | Stress | ✅ PASS | loader_threads=4, agent_threads=3, ledger_rows=125, backward_time_jumps=0 |
| 3. Ledger Throughput & SEAL Integrity | Stress | ✅ PASS | rows_committed=6500, sustained_tps=7655.1, burst_tps=16436.6, burst_ratio_vs_sustained=2.147 |
| 4. Adversarial Network Attacks | Stress | ✅ PASS | cycles_attempted=60, cycles_delivered=11, cycles_degraded_locally_buffered=49, heartbeat_survival_ratio=2.52 |

## Verification Phase
```json
{
  "ok": true,
  "ledgers_audited": 3,
  "total_rows": 13245,
  "temporal_anomalies_total": 0,
  "seal_failures_total": 0,
  "audit_jsonl_chain": null,
  "tamper_control": {
    "ran": true,
    "source": "tc3_ledger.db",
    "tamper_detected": true,
    "sample_error": "seq 6001: seal mismatch \u2014 payload/time edited"
  }
}
```
