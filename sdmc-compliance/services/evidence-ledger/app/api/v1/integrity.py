"""
Integrity verification endpoint.

GET /v1/integrity/verify - Verify entire hash chain

Per NIST SP 800-53 AU-9 (Protection of Audit Information)
Per 21 CFR Part 11 §11.10(a) (System Validation)
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.repo.evidence_repo import EvidenceRepo
from app.schemas.evidence import IntegrityVerifyResponse

router = APIRouter(prefix="/v1/integrity", tags=["integrity"])


@router.get(
    "/verify",
    response_model=IntegrityVerifyResponse,
    summary="Verify cryptographic integrity of all evidence records",
    description=(
        "Recomputes SHA-256 hash for every evidence record and verifies "
        "the hash chain linkage. Returns ok=true only if ALL records pass. "
        "Any failure indicates potential tampering. "
        "Per NIST SP 800-53 AU-9 (Protection of Audit Information)."
    ),
)
async def verify_integrity(
    db: AsyncSession = Depends(get_db),
) -> IntegrityVerifyResponse:
    """
    Verify hash chain integrity of all evidence records.

    Per NIST SP 800-53 AU-9 (Protection of Audit Information)
    Per 21 CFR Part 11 §11.10(a) (System Validation)
    """
    repo = EvidenceRepo(db)
    ok, checked, errors = await repo.verify_chain()
    return IntegrityVerifyResponse(ok=ok, checked=checked, errors=errors)
