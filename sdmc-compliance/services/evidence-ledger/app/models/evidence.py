"""
SQLAlchemy ORM for evidence_records table.

CRITICAL: This model must exactly match migrations/001_init_permits_schema.sql.
Any column mismatch causes silent data loss.

Per 21 CFR Part 11 §11.10(e) - Audit Trail Requirements
Per NIST SP 800-53 AU-9 (Protection of Audit Information)
"""
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Index, JSON, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column
# NOTE: Production PostgreSQL migration uses JSONB (see 001_init_permits_schema.sql).
# The ORM uses the cross-dialect JSON type so unit tests can run on SQLite without
# installing asyncpg or a live Postgres instance.

from app.db import Base


class EvidenceRecord(Base):
    """
    Immutable compliance evidence record.

    Stores cryptographically-linked gate decisions for San Diego building
    permit compliance. Records are append-only; the database enforces
    no-update/no-delete via SQL rules.

    Per NIST SP 800-53 AU-11 (Audit Record Retention)
    Per 21 CFR Part 11 §11.10(e) (Audit Trail)
    """
    __tablename__ = "evidence_records"

    # Per NIST SP 800-53 AU-3: unique identifier for each audit record
    evidence_id: Mapped[str] = mapped_column(Text, primary_key=True)

    # Gate identifier: gate-001-code-validation | gate-002-plan-review | gate-003-inspection
    gate_id: Mapped[str] = mapped_column(Text, nullable=False)

    # OPA decision output (PASS/FAIL + reasons) as JSONB
    decision_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    # Complete gate inputs for audit completeness
    # Per 21 CFR Part 11 §11.10(e): must capture all inputs
    inputs_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    # Server-computed SHA-256 hash - NEVER from client
    # Per NIST SP 800-53 SC-13: FIPS 140-2 approved algorithm
    # Format enforced: "sha256:<64-hex-chars>"
    evidence_hash: Mapped[str] = mapped_column(Text, nullable=False)

    # Hash of previous record for tamper-evident chain
    # Per 21 CFR Part 11 §11.10(e): sequential ordering requirement
    previous_hash: Mapped[str] = mapped_column(Text, nullable=False)

    # Digital signature of signing official
    # Per NIST SP 800-53 IA-2: identification and authentication
    # Per 21 CFR Part 11 §11.50: electronic signature requirements
    signature: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Server-generated timestamp - NEVER accept from client
    # Per NIST SP 800-53 AU-8: accurate time stamp requirement
    # CURRENT_TIMESTAMP is ISO SQL standard; equivalent to now() in PostgreSQL
    # and the only compatible form for SQLite (used in unit tests).
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False,
    )

    # Identity of signing official
    # Per NIST SP 800-53 IA-2: identity must be captured
    signer_id: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        # Mirrors idx_evidence_gate_id in 001_init_permits_schema.sql
        Index("idx_evidence_gate_id", "gate_id"),
        # Note: SQL migration declares this as DESC (created_at DESC).
        # SQLAlchemy metadata reflects the index name but not the sort direction.
        # The actual DESC index is created by migrations/001_init_permits_schema.sql.
        Index("idx_evidence_created_at", "created_at"),
        # Mirrors idx_evidence_inputs_permit (GIN) in 001_init_permits_schema.sql
        Index("idx_evidence_inputs_permit", "inputs_json", postgresql_using="gin"),
    )

    def __repr__(self) -> str:
        return f"<EvidenceRecord id={self.evidence_id!r} gate={self.gate_id!r} hash={self.evidence_hash[:16]!r}>"
