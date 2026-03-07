"""
Evidence record API endpoints.

POST /v1/evidence   - Validate gate, store immutable record
GET  /v1/evidence/{id} - Retrieve record with full integrity metadata

Per NIST SP 800-53 AU-6 (Audit Review, Analysis, and Reporting)
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.repo.evidence_repo import EvidenceRepo
from app.schemas.evidence import EvidenceCreate, EvidenceResponse, IntegrityOut
from app.services.opa_gate import evaluate_gate

router = APIRouter(prefix="/v1/evidence", tags=["evidence"])


def _to_response(record) -> EvidenceResponse:
    """
    Convert flat ORM record to nested API response schema.

    The ORM EvidenceRecord has flat columns (evidence_hash, previous_hash,
    signature). EvidenceResponse nests these under integrity: IntegrityOut.
    Direct model_validate(record) would fail - manual construction required.
    Per schemas/evidence.py contract note.
    """
    return EvidenceResponse(
        evidence_id=record.evidence_id,
        gate_id=record.gate_id,
        decision=record.decision_json,
        inputs=record.inputs_json,
        integrity=IntegrityOut(
            evidence_hash=record.evidence_hash,
            previous_hash=record.previous_hash,
            signature=record.signature,
        ),
        created_at=record.created_at,
        signer_id=record.signer_id,
    )


@router.post(
    "",
    response_model=EvidenceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create evidence record after gate validation",
    description=(
        "Evaluates the specified SDMC compliance gate via OPA, then stores "
        "an immutable evidence record with server-computed SHA-256 hash. "
        "Client-provided hashes are ignored per NIST SP 800-53 AC-3."
    ),
)
async def create_evidence(
    body: EvidenceCreate,
    db: AsyncSession = Depends(get_db),
) -> EvidenceResponse:
    """
    Create an evidence record.

    Gate evaluation happens before storage. If the gate FAILs,
    returns 422 with validation errors from OPA policy.

    Per SDMC §129.0302 (Building Permit Requirements)
    Per NIST SP 800-53 AU-3 (Content of Audit Records)
    """
    # Evaluate gate policy in OPA
    try:
        gate_report = await evaluate_gate(body.gate_id, body.inputs)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"OPA policy evaluation failed: {exc}",
        )

    decision = gate_report.get("decision", "FAIL")
    validation_errors = gate_report.get("validation_errors", [])

    if decision != "PASS":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": "Gate validation failed - evidence not stored",
                "gate_id": body.gate_id,
                "decision": decision,
                "validation_errors": validation_errors,
            },
        )

    repo = EvidenceRepo(db)
    record = await repo.create(body)
    return _to_response(record)


@router.get(
    "/{evidence_id}",
    response_model=EvidenceResponse,
    summary="Retrieve evidence record by ID",
    description=(
        "Returns the complete evidence record including server-computed "
        "integrity metadata. Used for audit and legal defense purposes. "
        "Per NIST SP 800-53 AU-6 (Audit Review)."
    ),
)
async def get_evidence(
    evidence_id: str,
    db: AsyncSession = Depends(get_db),
) -> EvidenceResponse:
    """
    Retrieve a single evidence record.

    Per NIST SP 800-53 AU-6 (Audit Review, Analysis, and Reporting)
    """
    repo = EvidenceRepo(db)
    record = await repo.get_by_id(evidence_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence record '{evidence_id}' not found",
        )
    return _to_response(record)
