"""
San Diego Municipal Code Compliance - Evidence Ledger Service.

Production FastAPI application implementing cryptographic audit trail
for SDMC building permit compliance.

Regulatory Framework:
  - San Diego Municipal Code (SDMC) Title 14, Division 2
  - NIST SP 800-53 Security Controls (AU, IA, SC series)
  - FDA 21 CFR Part 11 Electronic Records Integrity Model

Per NIST SP 800-53 SA-11 (Developer Testing and Evaluation)
"""
from contextlib import asynccontextmanager

import sqlalchemy
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.api.v1.evidence import router as evidence_router
from app.api.v1.integrity import router as integrity_router
from app.db import engine
from app.ui_router import router as ui_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup/shutdown lifecycle manager.

    Verifies database connectivity on startup to fail fast if the
    database is unreachable. Disposes of connection pool on shutdown.
    Per NIST SP 800-53 CP-10 (System Recovery and Reconstitution).
    """
    # Verify database connectivity on startup
    async with engine.connect() as conn:
        await conn.execute(sqlalchemy.text("SELECT 1"))
    yield
    await engine.dispose()


app = FastAPI(
    title="SDMC Evidence Ledger",
    description=(
        "Cryptographically-verifiable audit trail for San Diego Municipal "
        "Code building permit compliance. Implements NIST SP 800-53 and "
        "21 CFR Part 11 integrity controls."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(evidence_router)
app.include_router(integrity_router)
app.include_router(ui_router)


@app.get("/health/ready", tags=["health"])
async def health_ready():
    """
    Readiness probe.

    Returns 200 when the service is ready to receive traffic.
    Per NIST SP 800-53 CP-10 (System Recovery and Reconstitution).
    """
    return JSONResponse({"status": "ready", "service": "evidence-ledger"})
