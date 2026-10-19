"""Edge-Agentic Validation Benchmark Suite for the Sovereign Time System (STS)
and the Event-Driven Assurance Ledger.

Implements the four-category test matrix from the whitepaper plan:

  1. Temporal Isolation & Drift   -> bench/sts_time.py + tc1_ntp_poisoning.py
  2. High-Frequency Jitter        -> tc2_jitter_saturation.py
  3. Ledger Throughput & SEAL     -> tc3_ledger_throughput.py
  4. Adversarial Network Attacks  -> tc4_network_adversary.py

Execution methodology (see bench/run_benchmark.py):
  Baseline Phase  -> nominal conditions, record tick precision / write speeds
  Stress Phase    -> in-process fault injection (time skew, CPU load, packet
                     loss emulation) while the STS clock and ledger are active
  Verification    -> audit scripts re-hash the produced SQLite ledger and JSONL
                     assurance chain and assert zero temporal anomalies.

The suite is dependency-free (stdlib only) so it runs on minimal edge nodes;
hardware-level injections (real netem / stress-ng) are provided as optional
shell helpers in bench/scripts/ for rig operators with root access.
"""
