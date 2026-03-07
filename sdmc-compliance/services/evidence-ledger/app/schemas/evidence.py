"""
Pydantic v2 schemas for the Evidence Ledger API.

SECURITY NOTE: The `integrity` field on EvidenceCreate carries
client-provided hash/previous_hash values that are IGNORED by the
repository. Only `signature` and `signer_id` are used from the client.
The repository always recomputes evidence_hash and previous_hash
server-side.

Per NIST SP 800-53 AC-3 (Access Enforcement)
"""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class IntegrityIn(BaseModel):
    """
    Client-provided integrity fields.
    evidence_hash and previous_hash are IGNORED (security control).
    Only signature passes through.
    """
    evidence_hash: str = Field(
        default="",
        description="IGNORED: server always recomputes this field"
    )
    previous_hash: str = Field(
        default="",
        description="IGNORED: server always links to last stored hash"
    )
    signature: str = Field(
        default="",
        description="Base64-encoded digital signature of signing official"
    )


class IntegrityOut(BaseModel):
    """Server-computed integrity fields returned to client."""
    evidence_hash: str = Field(
        description="SHA-256 hash computed by server. Format: sha256:<64hex>"
    )
    previous_hash: str = Field(
        description="Hash of immediately preceding evidence record"
    )
    signature: str = Field(
        description="Digital signature of signing official"
    )


class EvidenceCreate(BaseModel):
    """
    Request body for POST /v1/evidence.

    The server ignores integrity.evidence_hash and integrity.previous_hash.
    It computes evidence_hash from (evidence_id, gate_id, decision, inputs,
    previous_hash) and chains previous_hash to the last stored record.
    """
    evidence_id: str = Field(
        description="Unique identifier. Format: BP-YYYY-#####-GATE00N-YYYYMMDD"
    )
    gate_id: str = Field(
        description="Gate identifier: gate-001-code-validation | gate-002-plan-review | gate-003-inspection"
    )
    decision: dict[str, Any] = Field(
        description="OPA gate decision output (result, reasons)"
    )
    inputs: dict[str, Any] = Field(
        description="Gate inputs (permit_id, code sections, plans, etc.)"
    )
    integrity: IntegrityIn = Field(
        description="Integrity envelope. evidence_hash/previous_hash ignored by server."
    )
    signer_id: str = Field(
        description="Email of signing official. Per NIST SP 800-53 IA-2."
    )


class EvidenceResponse(BaseModel):
    """
    Response for GET /v1/evidence/{id} and POST /v1/evidence.
    All fields reflect actual database values.
    """
    evidence_id: str
    gate_id: str
    decision: dict[str, Any]
    inputs: dict[str, Any]
    integrity: IntegrityOut
    created_at: datetime
    signer_id: str

    # IMPORTANT: Cannot use model_validate(orm_record) directly.
    # The ORM model (EvidenceRecord) is flat - evidence_hash, previous_hash,
    # and signature are top-level columns. This schema nests them under
    # integrity: IntegrityOut. The repository/router must manually construct
    # IntegrityOut and assemble EvidenceResponse. See api/v1/evidence.py _to_response().
    model_config = {"from_attributes": True}


class IntegrityVerifyResponse(BaseModel):
    """Response for GET /v1/integrity/verify."""
    ok: bool = Field(description="True if all records pass hash chain verification")
    checked: int = Field(description="Number of records verified")
    errors: list[str] = Field(
        default_factory=list,
        description="List of evidence_ids with integrity failures"
    )


class GateEvalRequest(BaseModel):
    """Internal: OPA gate evaluation request."""
    gate_package: str
    input_data: dict[str, Any]


class GateEvalResponse(BaseModel):
    """Internal: OPA gate evaluation response."""
    decision: str  # "PASS" or "FAIL"
    validation_errors: list[str]
    raw_report: dict[str, Any]
