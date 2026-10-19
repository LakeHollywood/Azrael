-- ============================================================================
-- db-init/01_schema.sql — OPTIONAL negative-control schema (PostgreSQL)
-- ----------------------------------------------------------------------------
-- The Sovereign Time System ledger is an append-only, SHA-256 hash-chained
-- SQLite store (bench/sts_time.py::AssuranceLedger). This Postgres mirror
-- exists ONLY for the containerized harness (docker-compose.yml, profile
-- "adversarial-controls") so regression tests can PROVE that no STS agent
-- or pipeline ever touches it: killing this database mid-run must leave
-- every seal, ordering invariant, and buffered event untouched.
-- Schema mirrors the SEAL row layout 1:1 for byte-comparable audits.
-- ============================================================================

CREATE TABLE IF NOT EXISTS ledger (
    seq               BIGINT PRIMARY KEY,
    mono_ns           BIGINT      NOT NULL,
    utc_wall          DOUBLE PRECISION NOT NULL,
    stream            TEXT        NOT NULL,
    payload           TEXT        NOT NULL,
    prev_seal         CHAR(64)    NOT NULL,
    seal_hash         CHAR(64)    NOT NULL,
    commit_latency_ms REAL        NOT NULL
);

CREATE INDEX IF NOT EXISTS ledger_mono_idx ON ledger (mono_ns);
CREATE INDEX IF NOT EXISTS ledger_stream_idx ON ledger (stream);

-- Append-only enforcement at the DB level (defense-in-depth analogue of the
-- SQLite trigger used in bench/sts_time.py): no UPDATE, no DELETE.
CREATE OR REPLACE FUNCTION reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'SEAL mirror is append-only: % forbidden', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ledger_append_only ON ledger;
CREATE TRIGGER ledger_append_only
    BEFORE UPDATE OR DELETE ON ledger
    FOR EACH ROW EXECUTE FUNCTION reject_mutation();

GRANT SELECT, INSERT ON ledger TO validator;
GRANT USAGE, SELECT ON SEQUENCE ledger_seq_seq TO validator;
