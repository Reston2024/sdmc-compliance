-- migrations/001_init_permits_schema.sql
-- San Diego Municipal Code Compliance - Evidence Records Schema
-- Per NIST SP 800-53 AU-11 (Audit Record Retention)
-- Per 21 CFR Part 11 §11.10(e) (Audit Trail)

CREATE TABLE IF NOT EXISTS evidence_records (
    -- Primary identifier - permit + gate combination
    -- Per NIST SP 800-53 AU-3 (Content of Audit Records)
    evidence_id     TEXT        PRIMARY KEY,

    -- Gate identifier (gate-001-code-validation, gate-002-plan-review, gate-003-inspection)
    gate_id         TEXT        NOT NULL,

    -- OPA gate decision result stored as JSON (PASS/FAIL + reasons)
    decision_json   JSONB       NOT NULL,

    -- Gate input data stored as JSON for audit completeness
    -- Per 21 CFR Part 11 §11.10(e) - must capture inputs
    inputs_json     JSONB       NOT NULL,

    -- SHA-256 hash of this record - server computed, never client-provided
    -- Per NIST SP 800-53 SC-13 (Cryptographic Protection)
    -- Format: "sha256:<64-hex-chars>"
    evidence_hash   TEXT        NOT NULL,

    -- Hash of immediately preceding record for chain integrity
    -- Per 21 CFR Part 11 §11.10(e) - sequential ordering
    -- Genesis record uses 64 zero-hex-chars
    previous_hash   TEXT        NOT NULL,

    -- Inspector/reviewer digital signature (base64 encoded)
    -- Per NIST SP 800-53 IA-2 (Identification and Authentication)
    -- Per 21 CFR Part 11 §11.50 (Electronic Signatures)
    signature       TEXT        NOT NULL DEFAULT '',

    -- Server-generated timestamp - NEVER client-provided
    -- Per NIST SP 800-53 AU-8 (Time Stamps)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Identity of signing official (email address)
    -- Per NIST SP 800-53 IA-2 (Identification)
    signer_id       TEXT        NOT NULL
);

-- Index for permit-based queries (city auditor use case)
CREATE INDEX IF NOT EXISTS idx_evidence_inputs_permit
    ON evidence_records USING GIN (inputs_json);

-- Index for time-ordered queries (hash chain verification)
CREATE INDEX IF NOT EXISTS idx_evidence_created_at
    ON evidence_records (created_at DESC);

-- Index for gate-based filtering
CREATE INDEX IF NOT EXISTS idx_evidence_gate_id
    ON evidence_records (gate_id);

-- Prevent modification of existing records (append-only enforcement)
-- Per NIST SP 800-53 AU-11 (Audit Record Retention)
CREATE RULE no_update_evidence AS ON UPDATE TO evidence_records DO INSTEAD NOTHING;
CREATE RULE no_delete_evidence AS ON DELETE TO evidence_records DO INSTEAD NOTHING;
