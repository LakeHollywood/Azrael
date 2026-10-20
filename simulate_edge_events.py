#!/usr/bin/env python3
"""
STS Edge Event Producer
Simulates the edge application generating anchors and queuing them for the daemon.
"""
import sqlite3
import time
import json
import os

QUEUE_DB = os.getenv("STS_QUEUE_DB", "/tmp/sts/anchor_queue.db")

def ensure_db():
    os.makedirs(os.path.dirname(QUEUE_DB), exist_ok=True)
    with sqlite3.connect(QUEUE_DB) as conn:
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS quarantine_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ledger_seq INTEGER UNIQUE,
                payload TEXT,
                signature TEXT,
                status TEXT DEFAULT 'PENDING',
                retry_count INTEGER DEFAULT 0,
                next_retry REAL DEFAULT 0,
                created_at REAL DEFAULT (strftime('%s', 'now'))
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_status_retry ON quarantine_queue(status, next_retry);")
        conn.commit()

def produce_anchor(ledger_seq, event_type, risk_score):
    payload = json.dumps({
        "timestamp": time.time(),
        "event": event_type,
        "device": "orin-splinter-01",
        "metrics": {"cpu_temp": 65.0, "net_latency_ms": 120}
    })
    signature = "MOCK_ED25519_SIG_" + str(ledger_seq)

    with sqlite3.connect(QUEUE_DB) as conn:
        try:
            conn.execute("""
                INSERT INTO quarantine_queue (ledger_seq, payload, signature, status, next_retry)
                VALUES (?, ?, ?, 'PENDING', 0)
            """, (ledger_seq, payload, signature))
            conn.commit()
            print(f"✅ Produced Anchor Seq #{ledger_seq} (Risk Score: {risk_score})")
        except sqlite3.IntegrityError:
            print(f"⚠️ Anchor Seq #{ledger_seq} already exists.")

if __name__ == "__main__":
    ensure_db()
    print("🚀 Starting Edge Event Producer (Press Ctrl+C to stop)")

    seq = 1000
    try:
        while True:
            # Simulate normal telemetry
            produce_anchor(seq, "TELEMETRY_ANCHOR", 15)
            seq += 1
            time.sleep(2)  # Produce one anchor every 2 seconds

            # Simulate occasional high-risk event
            if seq % 5 == 0:
                produce_anchor(seq, "STRESS_ANCHOR", 75)
                seq += 1

    except KeyboardInterrupt:
        print("\n🛑 Producer stopped.")
