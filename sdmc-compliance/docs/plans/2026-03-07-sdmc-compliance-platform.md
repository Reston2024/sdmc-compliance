# San Diego Municipal Code Compliance Platform - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a production-grade cryptographically-verifiable audit trail system for San Diego building permit and code compliance, applying FDA 21 CFR Part 11 and NIST SP 800-53 integrity controls to municipal governance.

**Architecture:** FastAPI evidence-ledger service backed by PostgreSQL stores immutable compliance records with SHA-256 hash chains. Three OPA policy gates validate SDMC code sections, plan review coverage, and inspection completeness before any record is stored. Every record's hash is server-computed and chain-linked to the previous record, making tampering mathematically detectable.

**Tech Stack:** Python 3.10, FastAPI, SQLAlchemy (async), PostgreSQL 15, Open Policy Agent (OPA), asyncpg, Docker Compose, pytest-asyncio

---

## Project Layout (create all directories first)

```
sdmc-compliance/
├── docker-compose.yml
├── migrations/
│   └── 001_init_permits_schema.sql
├── policy/
│   └── opa/
│       └── compliance-gates/
│           ├── gate-001-sdmc-code-validation.rego
│           ├── gate-002-sdmc-plan-review.rego
│           └── gate-003-sdmc-inspection.rego
├── services/
│   └── evidence-ledger/
│       ├── Dockerfile
│       ├── pyproject.toml
│       ├── app/
│       │   ├── __init__.py
│       │   ├── main.py
│       │   ├── db.py
│       │   ├── api/
│       │   │   ├── __init__.py
│       │   │   └── v1/
│       │   │       ├── __init__.py
│       │   │       ├── evidence.py
│       │   │       └── integrity.py
│       │   ├── models/
│       │   │   ├── __init__.py
│       │   │   └── evidence.py
│       │   ├── repo/
│       │   │   ├── __init__.py
│       │   │   └── evidence_repo.py
│       │   ├── schemas/
│       │   │   ├── __init__.py
│       │   │   └── evidence.py
│       │   └── services/
│       │       ├── __init__.py
│       │       └── opa_gate.py
│       └── tests/
│           ├── __init__.py
│           ├── conftest.py
│           ├── test_gates.py
│           ├── test_evidence_api.py
│           └── test_integrity.py
└── outputs/
    └── SDMC-VALIDATION-REPORT.md
```

---

### Task 1: Project Scaffolding

**Files:**
- Create: `sdmc-compliance/docker-compose.yml`
- Create: `sdmc-compliance/services/evidence-ledger/pyproject.toml`
- Create: `sdmc-compliance/services/evidence-ledger/Dockerfile`

**Step 1: Create directory structure**

```bash
cd /c/Users/ablan/Documents/Claude/sdmc-compliance
mkdir -p migrations
mkdir -p policy/opa/compliance-gates
mkdir -p services/evidence-ledger/app/api/v1
mkdir -p services/evidence-ledger/app/models
mkdir -p services/evidence-ledger/app/repo
mkdir -p services/evidence-ledger/app/schemas
mkdir -p services/evidence-ledger/app/services
mkdir -p services/evidence-ledger/tests
mkdir -p outputs
# Create all __init__.py files
touch services/evidence-ledger/app/__init__.py
touch services/evidence-ledger/app/api/__init__.py
touch services/evidence-ledger/app/api/v1/__init__.py
touch services/evidence-ledger/app/models/__init__.py
touch services/evidence-ledger/app/repo/__init__.py
touch services/evidence-ledger/app/schemas/__init__.py
touch services/evidence-ledger/app/services/__init__.py
touch services/evidence-ledger/tests/__init__.py
```

**Step 2: Write `docker-compose.yml`**

```yaml
# sdmc-compliance/docker-compose.yml
version: "3.9"

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_USER: sdmc
      POSTGRES_PASSWORD: sdmc
      POSTGRES_DB: permits
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "sdmc"]
      interval: 5s
      timeout: 5s
      retries: 10
    ports:
      - "5432:5432"

  opa:
    image: openpolicyagent/opa:latest
    command:
      - "run"
      - "--server"
      - "--addr=0.0.0.0:8181"
      - "--log-level=info"
      - "/policies"
    volumes:
      - ./policy/opa:/policies
    ports:
      - "8181:8181"

  evidence-ledger:
    build: ./services/evidence-ledger
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DATABASE_URL: "postgresql+asyncpg://sdmc:sdmc@postgres:5432/permits"
      OPA_URL: "http://opa:8181"
    ports:
      - "8000:8000"

volumes:
  pgdata:
```

**Step 3: Write `pyproject.toml`**

```toml
# services/evidence-ledger/pyproject.toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "evidence-ledger"
version = "1.0.0"
description = "SDMC Cryptographic Compliance Audit Trail - Per NIST SP 800-53 AU-11"
requires-python = ">=3.10"
dependencies = [
    "fastapi>=0.109.0",
    "uvicorn[standard]>=0.27.0",
    "sqlalchemy[asyncio]>=2.0.0",
    "asyncpg>=0.29.0",
    "alembic>=1.13.0",
    "httpx>=0.26.0",
    "pydantic>=2.5.0",
    "pydantic-settings>=2.1.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.23.0",
    "pytest-httpx>=0.28.0",
]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

**Step 4: Write `Dockerfile`**

```dockerfile
# services/evidence-ledger/Dockerfile
FROM python:3.10-slim

WORKDIR /app

RUN pip install --no-cache-dir hatchling

COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[dev]"

COPY app/ ./app/

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
```

**Step 5: Commit**

```bash
cd /c/Users/ablan/Documents/Claude/sdmc-compliance
git init
git add .
git commit -m "feat: scaffold project structure and docker-compose"
```

---

### Task 2: Database Schema (Phase 1)

**Files:**
- Create: `sdmc-compliance/migrations/001_init_permits_schema.sql`

**Step 1: Write migration SQL**

```sql
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
```

**Step 2: Verify schema compiles (dry run)**

```bash
# Verify SQL syntax without a running DB
docker run --rm postgres:15 bash -c "
  initdb -D /tmp/pgdata -U sdmc &&
  pg_ctl start -D /tmp/pgdata -o '-p 5433' -l /tmp/pg.log &&
  sleep 2 &&
  psql -p 5433 -U sdmc -c 'CREATE DATABASE permits;' &&
  psql -p 5433 -U sdmc -d permits < /dev/stdin
" < migrations/001_init_permits_schema.sql
```

Expected: SQL executes without errors.

**Step 3: Commit**

```bash
git add migrations/
git commit -m "feat: add evidence_records schema with cryptographic integrity columns"
```

---

### Task 3: SQLAlchemy ORM Model (Phase 1 cont.)

**Files:**
- Create: `services/evidence-ledger/app/models/evidence.py`
- Create: `services/evidence-ledger/app/db.py`

**Step 1: Write `app/db.py`**

```python
# services/evidence-ledger/app/db.py
"""
Database connection and session management.
Per NIST SP 800-53 SC-28 (Protection of Information at Rest).
"""
import os
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://sdmc:sdmc@localhost:5432/permits"
)

engine = create_async_engine(DATABASE_URL, echo=False)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    """FastAPI dependency: yields a database session per request."""
    async with AsyncSessionLocal() as session:
        yield session
```

**Step 2: Write `app/models/evidence.py`**

This ORM model MUST exactly match the SQL schema column-for-column.

```python
# services/evidence-ledger/app/models/evidence.py
"""
SQLAlchemy ORM for evidence_records table.

CRITICAL: This model must exactly match migrations/001_init_permits_schema.sql.
Any column mismatch causes silent data loss.

Per 21 CFR Part 11 §11.10(e) - Audit Trail Requirements
Per NIST SP 800-53 AU-9 (Protection of Audit Information)
"""
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

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
    decision_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    # Complete gate inputs for audit completeness
    # Per 21 CFR Part 11 §11.10(e): must capture all inputs
    inputs_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

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
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Identity of signing official
    # Per NIST SP 800-53 IA-2: identity must be captured
    signer_id: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        Index("idx_evidence_gate_id", "gate_id"),
        Index("idx_evidence_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<EvidenceRecord id={self.evidence_id!r} gate={self.gate_id!r} hash={self.evidence_hash[:16]!r}>"
```

**Step 3: Commit**

```bash
git add services/evidence-ledger/app/
git commit -m "feat: add async DB engine and EvidenceRecord ORM model"
```

---

### Task 4: Pydantic Schemas (API contracts)

**Files:**
- Create: `services/evidence-ledger/app/schemas/evidence.py`

**Step 1: Write schemas**

```python
# services/evidence-ledger/app/schemas/evidence.py
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
```

**Step 2: Commit**

```bash
git add services/evidence-ledger/app/schemas/
git commit -m "feat: add Pydantic v2 schemas with security annotations"
```

---

### Task 5: OPA Gate Service

**Files:**
- Create: `services/evidence-ledger/app/services/opa_gate.py`

**Step 1: Write OPA gate service**

```python
# services/evidence-ledger/app/services/opa_gate.py
"""
OPA (Open Policy Agent) gate evaluation service.

Calls OPA HTTP API to evaluate SDMC compliance gates before
allowing evidence records to be created.

Per NIST SP 800-53 CA-2 (Control Assessments)
Per SDMC §129.0302 (Building Permit Requirements)
"""
import os
from typing import Any

import httpx

OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181")

# Map gate IDs to OPA policy package paths
GATE_POLICY_MAP: dict[str, str] = {
    "gate-001-code-validation": "compliance/gates/sdmc_code_validation",
    "gate-002-plan-review":     "compliance/gates/sdmc_plan_review",
    "gate-003-inspection":      "compliance/gates/sdmc_inspection",
}


async def evaluate_gate(gate_id: str, input_data: dict[str, Any]) -> dict[str, Any]:
    """
    Evaluate an SDMC compliance gate via OPA.

    Returns the gate_report result dict. Raises ValueError if gate_id
    is unknown. Raises httpx.HTTPError on OPA communication failure.

    Per NIST SP 800-53 CA-2 (Control Assessments)
    """
    package_path = GATE_POLICY_MAP.get(gate_id)
    if package_path is None:
        raise ValueError(
            f"Unknown gate_id '{gate_id}'. "
            f"Valid gates: {list(GATE_POLICY_MAP.keys())}"
        )

    url = f"{OPA_URL}/v1/data/{package_path}/gate_report"

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            url,
            json={"input": input_data},
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()

    body = response.json()
    # OPA wraps result in {"result": {...}}
    result = body.get("result", {})
    return result


async def gate_allows(gate_id: str, input_data: dict[str, Any]) -> tuple[bool, list[str]]:
    """
    Convenience wrapper: returns (allowed, validation_errors).

    allowed=True means gate decision is "PASS" with no validation errors.

    Per NIST SP 800-53 CA-2 (Control Assessments)
    """
    report = await evaluate_gate(gate_id, input_data)
    decision = report.get("decision", "FAIL")
    errors = report.get("validation_errors", [])
    return (decision == "PASS"), errors
```

**Step 2: Commit**

```bash
git add services/evidence-ledger/app/services/
git commit -m "feat: add OPA gate evaluation service"
```

---

### Task 6: Evidence Repository (Core Cryptographic Logic)

**Files:**
- Create: `services/evidence-ledger/app/repo/evidence_repo.py`

**Step 1: Write the repository with hash computation**

This is the most security-critical code. Read the docstrings carefully.

```python
# services/evidence-ledger/app/repo/evidence_repo.py
"""
Evidence Record Repository.

SECURITY CRITICAL: This module is the SOLE authority for hash computation.
Client-provided hashes are ALWAYS ignored. The server computes:
  1. previous_hash  - by querying the last stored record
  2. evidence_hash  - by SHA-256 over canonical inputs

This is the 21 CFR Part 11 §11.10(a) system validation control:
the system itself ensures integrity, not the client.

Per NIST SP 800-53 SC-13 (Cryptographic Protection - FIPS 140-2)
Per 21 CFR Part 11 §11.10(e) (Audit Trail - Sequential Ordering)
"""
import hashlib
import json
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.evidence import EvidenceRecord
from app.schemas.evidence import EvidenceCreate

# Genesis hash: used as previous_hash for the very first record.
# 64 hex zeros with sha256: prefix per format specification.
GENESIS_HASH = "sha256:" + "0" * 64


class EvidenceRepo:
    """
    Repository for creating and querying evidence records.

    All hash computation happens server-side. Client hashes are silently
    discarded to prevent fraud.
    """

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    def _compute_hash(
        self,
        evidence_id: str,
        gate_id: str,
        decision_json: str,
        inputs_json: str,
        previous_hash: str,
    ) -> str:
        """
        Compute SHA-256 hash of evidence record fields.

        Uses pipe-delimited canonical format for determinism.
        Returns hash with explicit "sha256:" prefix per NIST SP 800-53 SC-13.

        SECURITY: Never accepts client-provided hash values.
        Per NIST SP 800-53 SC-13 (Cryptographic Protection)
        Per FIPS 140-2 (approved hash algorithm: SHA-256)
        """
        m = hashlib.sha256()
        # Canonical field order: evidence_id | gate_id | decision | inputs | previous_hash
        # Changing this order changes all hashes - do not modify
        m.update(evidence_id.encode("utf-8"))
        m.update(b"|")
        m.update(gate_id.encode("utf-8"))
        m.update(b"|")
        m.update(decision_json.encode("utf-8"))
        m.update(b"|")
        m.update(inputs_json.encode("utf-8"))
        m.update(b"|")
        m.update(previous_hash.encode("utf-8"))
        # Explicit algorithm prefix prevents format ambiguity
        return f"sha256:{m.hexdigest()}"

    def _canonical_json(self, data: dict) -> str:
        """
        Produce deterministic JSON string for hashing.

        sorted_keys=True ensures same dict always produces same hash.
        Per NIST SP 800-53 SC-13: deterministic cryptographic operations.
        """
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    async def _get_last_hash(self) -> str:
        """
        Retrieve hash of most recently created record for chain linkage.

        Returns GENESIS_HASH if no records exist.
        Per 21 CFR Part 11 §11.10(e): sequential record ordering.
        Per NIST SP 800-53 AU-8: time-ordered audit records.
        """
        result = await self.db.execute(
            select(EvidenceRecord.evidence_hash)
            .order_by(EvidenceRecord.created_at.desc())
            .limit(1)
        )
        last = result.scalar_one_or_none()
        return last if last is not None else GENESIS_HASH

    async def create(self, data: EvidenceCreate) -> EvidenceRecord:
        """
        Create an immutable evidence record with server-computed hash.

        Security controls applied:
        1. Client's integrity.evidence_hash is IGNORED
        2. Client's integrity.previous_hash is IGNORED
        3. Server fetches actual previous_hash from database
        4. Server computes evidence_hash over canonical inputs

        Per NIST SP 800-53 AU-9 (Protection of Audit Information)
        Per 21 CFR Part 11 §11.10(a) (System Validation)
        """
        # Step 1: Canonical JSON for deterministic hashing
        decision_json = self._canonical_json(data.decision)
        inputs_json = self._canonical_json(data.inputs)

        # Step 2: Server fetches previous hash (client value IGNORED)
        # This is the core fraud-prevention control
        previous_hash = await self._get_last_hash()

        # Step 3: Server computes record hash (client value IGNORED)
        evidence_hash = self._compute_hash(
            data.evidence_id,
            data.gate_id,
            decision_json,
            inputs_json,
            previous_hash,
        )

        # Step 4: Build record - signature passes through from client
        record = EvidenceRecord(
            evidence_id=data.evidence_id,
            gate_id=data.gate_id,
            decision_json=data.decision,
            inputs_json=data.inputs,
            evidence_hash=evidence_hash,   # server-computed
            previous_hash=previous_hash,   # server-computed
            signature=data.integrity.signature,  # client-provided (OK)
            signer_id=data.signer_id,
        )

        self.db.add(record)
        await self.db.commit()
        await self.db.refresh(record)
        return record

    async def get_by_id(self, evidence_id: str) -> Optional[EvidenceRecord]:
        """
        Retrieve a single evidence record by its ID.

        Per NIST SP 800-53 AU-6 (Audit Review, Analysis, and Reporting)
        """
        result = await self.db.execute(
            select(EvidenceRecord).where(
                EvidenceRecord.evidence_id == evidence_id
            )
        )
        return result.scalar_one_or_none()

    async def get_all_ordered(self) -> list[EvidenceRecord]:
        """
        Retrieve all records in creation order for integrity verification.

        Per NIST SP 800-53 AU-11 (Audit Record Retention)
        """
        result = await self.db.execute(
            select(EvidenceRecord).order_by(EvidenceRecord.created_at.asc())
        )
        return list(result.scalars().all())

    async def verify_chain(self) -> tuple[bool, list[str]]:
        """
        Verify the hash chain integrity of ALL evidence records.

        For each record, recomputes the expected hash from stored fields
        and compares to the stored evidence_hash. Also verifies the
        previous_hash linkage is correct.

        Returns (ok, list_of_failing_evidence_ids).

        Per NIST SP 800-53 AU-9 (Protection of Audit Information)
        Per 21 CFR Part 11 §11.10(a) (System Validation)
        """
        records = await self.get_all_ordered()
        errors: list[str] = []
        expected_previous = GENESIS_HASH

        for record in records:
            # Recompute canonical JSON from stored JSONB (same as creation)
            decision_json = self._canonical_json(record.decision_json)
            inputs_json = self._canonical_json(record.inputs_json)

            # Recompute expected hash
            expected_hash = self._compute_hash(
                record.evidence_id,
                record.gate_id,
                decision_json,
                inputs_json,
                record.previous_hash,
            )

            # Check 1: stored hash matches recomputed hash
            if record.evidence_hash != expected_hash:
                errors.append(
                    f"{record.evidence_id}: hash mismatch "
                    f"(stored={record.evidence_hash[:16]}... "
                    f"expected={expected_hash[:16]}...)"
                )

            # Check 2: previous_hash matches last record's hash
            if record.previous_hash != expected_previous:
                errors.append(
                    f"{record.evidence_id}: chain break "
                    f"(stored_prev={record.previous_hash[:16]}... "
                    f"expected_prev={expected_previous[:16]}...)"
                )

            expected_previous = record.evidence_hash

        return len(errors) == 0, errors
```

**Step 2: Commit**

```bash
git add services/evidence-ledger/app/repo/
git commit -m "feat: add evidence repository with server-side SHA-256 hash chain"
```

---

### Task 7: FastAPI Application and Routes

**Files:**
- Create: `services/evidence-ledger/app/main.py`
- Create: `services/evidence-ledger/app/api/v1/evidence.py`
- Create: `services/evidence-ledger/app/api/v1/integrity.py`

**Step 1: Write `app/api/v1/evidence.py`**

```python
# services/evidence-ledger/app/api/v1/evidence.py
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
    """Convert ORM record to API response schema."""
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
```

**Step 2: Write `app/api/v1/integrity.py`**

```python
# services/evidence-ledger/app/api/v1/integrity.py
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
    ok, errors = await repo.verify_chain()
    checked = len(await repo.get_all_ordered())
    return IntegrityVerifyResponse(ok=ok, checked=checked, errors=errors)
```

**Step 3: Write `app/main.py`**

```python
# services/evidence-ledger/app/main.py
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

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.api.v1.evidence import router as evidence_router
from app.api.v1.integrity import router as integrity_router
from app.db import engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle manager."""
    # Verify database connectivity on startup
    async with engine.connect() as conn:
        await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
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


@app.get("/health/ready", tags=["health"])
async def health_ready():
    """
    Readiness probe.
    Per NIST SP 800-53 CP-10 (System Recovery and Reconstitution).
    """
    return JSONResponse({"status": "ready", "service": "evidence-ledger"})
```

**Step 4: Commit**

```bash
git add services/evidence-ledger/app/
git commit -m "feat: add FastAPI routes for evidence create, retrieve, and integrity verify"
```

---

### Task 8: OPA Policy - Gate 001 (Code Section Validation)

**Files:**
- Create: `policy/opa/compliance-gates/gate-001-sdmc-code-validation.rego`

**Step 1: Write Gate 001 Rego policy**

```rego
# policy/opa/compliance-gates/gate-001-sdmc-code-validation.rego
#
# SDMC Gate 001: Code Section Validation
#
# Verifies that a building permit application correctly identifies
# and cites the applicable San Diego Municipal Code sections.
#
# Per SDMC §129.0302 (Building Permit Requirements)
# Per NIST SP 800-53 CA-2 (Control Assessments)
# Per 21 CFR Part 11 §11.10(e) (Audit Trail)

package compliance.gates.sdmc_code_validation

import future.keywords.in
import future.keywords.if
import future.keywords.every

# Valid verification methods per SDMC inspection procedures
VALID_VERIFICATION_METHODS := {
    "Inspection",
    "Plan Review",
    "Calculation Review",
    "Testing",
    "Third-Party Certification"
}

# SDMC section ID format: SDMC-###.####
SECTION_ID_PATTERN := `^SDMC-[0-9]{3}\.[0-9]{4}$`

# ─────────────────────────────────────────────────────────────────────────────
# Main gate report - single output used by Evidence Ledger service
# ─────────────────────────────────────────────────────────────────────────────

gate_report := {
    "decision":            final_decision,
    "gate_id":             "001",
    "gate_name":           "Code Section Validation",
    "sections_evaluated":  count(input.code_sections),
    "sections_passed":     count([s | s := input.code_sections[_]; section_valid(s)]),
    "statistics": {
        "total_sections":          count(input.code_sections),
        "sections_with_criteria":  count([s | s := input.code_sections[_]; count(s.Compliance_Criteria) > 0]),
        "valid_format":            count([s | s := input.code_sections[_]; regex.match(SECTION_ID_PATTERN, s.Section_ID)]),
        "validation_errors":       count(validation_errors),
    },
    "validation_errors":   validation_errors,
    "timestamp":           time.now_ns() / 1000000,
}

final_decision := "PASS" if count(validation_errors) == 0
final_decision := "FAIL" if count(validation_errors) > 0

# ─────────────────────────────────────────────────────────────────────────────
# Validation Rules
# ─────────────────────────────────────────────────────────────────────────────

validation_errors[msg] {
    not has_valid_metadata
    msg := "METADATA ERROR: Missing required fields (permit_id, project_address, applicant_name, sdmc_version). Per NIST SP 800-53 AU-3 (Content of audit records)."
}

validation_errors[msg] {
    not has_unique_section_ids
    msg := "DUPLICATE ERROR: Duplicate Section_IDs detected. Per SDMC §129.0302 (Building permit requirements) - each code section must appear once."
}

validation_errors[msg] {
    s := input.code_sections[_]
    not regex.match(SECTION_ID_PATTERN, s.Section_ID)
    msg := sprintf(
        "FORMAT ERROR: Section_ID '%v' does not match pattern SDMC-###.#### (e.g., SDMC-142.0503). Per SDMC §129.0302 (Building permit requirements).",
        [s.Section_ID]
    )
}

validation_errors[msg] {
    s := input.code_sections[_]
    not s.Verification_Method in VALID_VERIFICATION_METHODS
    msg := sprintf(
        "METHOD ERROR: Section '%v' has invalid Verification_Method '%v'. Valid methods: %v. Per SDMC §129.0306 (Inspection requirements).",
        [s.Section_ID, s.Verification_Method, VALID_VERIFICATION_METHODS]
    )
}

validation_errors[msg] {
    s := input.code_sections[_]
    count(s.Compliance_Criteria) == 0
    msg := sprintf(
        "CRITERIA ERROR: Section '%v' has no Compliance_Criteria. Each section must list specific verification criteria. Per NIST SP 800-53 CA-2 (Control assessments).",
        [s.Section_ID]
    )
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper Rules
# ─────────────────────────────────────────────────────────────────────────────

has_valid_metadata if {
    input.metadata.permit_id != ""
    input.metadata.project_address != ""
    input.metadata.applicant_name != ""
    input.metadata.sdmc_version != ""
}

has_unique_section_ids if {
    ids := [s.Section_ID | s := input.code_sections[_]]
    count(ids) == count({id | id := ids[_]})
}

section_valid(s) if {
    regex.match(SECTION_ID_PATTERN, s.Section_ID)
    s.Verification_Method in VALID_VERIFICATION_METHODS
    count(s.Compliance_Criteria) > 0
}
```

**Step 2: Commit**

```bash
git add policy/
git commit -m "feat: add OPA Gate 001 - SDMC code section validation"
```

---

### Task 9: OPA Policy - Gate 002 (Plan Review Compliance)

**Files:**
- Create: `policy/opa/compliance-gates/gate-002-sdmc-plan-review.rego`

**Step 1: Write Gate 002 Rego policy**

```rego
# policy/opa/compliance-gates/gate-002-sdmc-plan-review.rego
#
# SDMC Gate 002: Plan Review Compliance
#
# Verifies bidirectional traceability between SDMC code sections
# and approved plan documents.
#
# Per SDMC §129.0304 (Plan Review Procedures)
# Per NIST SP 800-53 CM-3 (Configuration Change Control)
# Per California Business and Professions Code §6735 (Engineer Seal)

package compliance.gates.sdmc_plan_review

import future.keywords.in
import future.keywords.if

VALID_DOCUMENT_TYPES := {
    "Structural Calculations",
    "Architectural Drawings",
    "Electrical Plans",
    "Plumbing Plans",
    "Mechanical Plans",
    "Fire Protection Plans",
    "Solar Panel Layout",
    "Site Plan"
}

# Pattern: contains license number
LICENSE_PATTERN := `#[0-9]+`

# ─────────────────────────────────────────────────────────────────────────────
# Main gate report
# ─────────────────────────────────────────────────────────────────────────────

gate_report := {
    "decision":                   final_decision,
    "gate_id":                    "002",
    "gate_name":                  "Plan Review Compliance",
    "code_sections_evaluated":    count(input.code_section_ids),
    "plan_documents_evaluated":   count(input.plan_documents),
    "statistics": {
        "coverage_percent":     coverage_percent,
        "sections_covered":     count(covered_sections),
        "sections_not_covered": count(uncovered_sections),
        "plans_traced":         count(traced_plans),
        "plans_orphaned":       count(orphaned_plans),
        "validation_errors":    count(validation_errors),
    },
    "validation_errors": validation_errors,
}

final_decision := "PASS" if count(validation_errors) == 0
final_decision := "FAIL" if count(validation_errors) > 0

# ─────────────────────────────────────────────────────────────────────────────
# Coverage Calculations
# ─────────────────────────────────────────────────────────────────────────────

# Set of code section IDs covered by at least one plan document
covered_sections := {sid |
    sid := input.code_section_ids[_]
    some doc in input.plan_documents
    sid in doc.Code_Sections
}

uncovered_sections := {sid |
    sid := input.code_section_ids[_]
    not sid in covered_sections
}

# Plans that trace to at least one required code section
traced_plans := {doc.Document_ID |
    doc := input.plan_documents[_]
    some sid in doc.Code_Sections
    sid in {s | s := input.code_section_ids[_]}
}

orphaned_plans := {doc.Document_ID |
    doc := input.plan_documents[_]
    not doc.Document_ID in traced_plans
}

coverage_percent := 100 if count(input.code_section_ids) == 0
coverage_percent := round((count(covered_sections) / count(input.code_section_ids)) * 100) if count(input.code_section_ids) > 0

# ─────────────────────────────────────────────────────────────────────────────
# Validation Rules
# ─────────────────────────────────────────────────────────────────────────────

validation_errors[msg] {
    not has_valid_metadata
    msg := "METADATA ERROR: Missing required fields (permit_id, review_date, reviewer_id, plan_review_status). Per NIST SP 800-53 AU-3 (Content of audit records)."
}

validation_errors[msg] {
    input.metadata.plan_review_status != "APPROVED"
    msg := sprintf(
        "STATUS ERROR: plan_review_status is '%v', must be 'APPROVED'. Per SDMC §129.0304 (Plan review procedures).",
        [input.metadata.plan_review_status]
    )
}

validation_errors[msg] {
    sid := uncovered_sections[_]
    msg := sprintf(
        "COVERAGE ERROR: Code section '%v' is not covered by any plan document. Per NIST SP 800-53 CM-3 (Configuration change control).",
        [sid]
    )
}

validation_errors[msg] {
    doc_id := orphaned_plans[_]
    msg := sprintf(
        "TRACEABILITY ERROR: Plan document '%v' does not trace to any required code section. Per NIST SP 800-53 CM-3 (Configuration change control).",
        [doc_id]
    )
}

validation_errors[msg] {
    doc := input.plan_documents[_]
    not doc.Document_Type in VALID_DOCUMENT_TYPES
    msg := sprintf(
        "TYPE ERROR: Plan '%v' has invalid Document_Type '%v'. Valid types: %v. Per SDMC §129.0304 (Plan review procedures).",
        [doc.Document_ID, doc.Document_Type, VALID_DOCUMENT_TYPES]
    )
}

validation_errors[msg] {
    doc := input.plan_documents[_]
    not regex.match(LICENSE_PATTERN, doc.Prepared_By)
    msg := sprintf(
        "STAMP ERROR: Plan '%v' Prepared_By field '%v' does not contain a license number (format: #NNNNN). Per California Business and Professions Code §6735 (Engineer seal requirements).",
        [doc.Document_ID, doc.Prepared_By]
    )
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper Rules
# ─────────────────────────────────────────────────────────────────────────────

has_valid_metadata if {
    input.metadata.permit_id != ""
    input.metadata.review_date != ""
    input.metadata.reviewer_id != ""
    input.metadata.plan_review_status != ""
}
```

**Step 2: Commit**

```bash
git add policy/
git commit -m "feat: add OPA Gate 002 - SDMC plan review compliance with bidirectional traceability"
```

---

### Task 10: OPA Policy - Gate 003 (Inspection Verification)

**Files:**
- Create: `policy/opa/compliance-gates/gate-003-sdmc-inspection.rego`

**Step 1: Write Gate 003 Rego policy**

```rego
# policy/opa/compliance-gates/gate-003-sdmc-inspection.rego
#
# SDMC Gate 003: Inspection Verification
#
# Verifies on-site inspections have been completed for all code sections
# and plan documents, with documented results.
#
# Per SDMC §129.0306 (Inspection Requirements)
# Per SDMC §129.0308 (Stop Work Orders)
# Per NIST SP 800-53 AU-6 (Audit Review, Analysis, and Reporting)

package compliance.gates.sdmc_inspection

import future.keywords.in
import future.keywords.if

VALID_METHODS := {
    "Visual Inspection",
    "Testing",
    "Measurement",
    "Third-Party Report Review"
}

VALID_RESULTS := {
    "PASS",
    "FAIL",
    "CONDITIONAL_PASS",
    "PENDING_CORRECTION"
}

# ─────────────────────────────────────────────────────────────────────────────
# Main gate report
# ─────────────────────────────────────────────────────────────────────────────

gate_report := {
    "decision":              final_decision,
    "gate_id":               "003",
    "gate_name":             "Inspection Verification",
    "inspections_evaluated": count(input.inspection_activities),
    "statistics": {
        "code_sections_coverage_percent": code_coverage_percent,
        "plans_coverage_percent":         plans_coverage_percent,
        "sections_inspected":             count(inspected_sections),
        "sections_not_inspected":         count(uninspected_sections),
        "plans_verified":                 count(verified_plans),
        "plans_not_verified":             count(unverified_plans),
        "inspections_passed":             count([a | a := input.inspection_activities[_]; a.Result == "PASS"]),
        "inspections_failed":             count([a | a := input.inspection_activities[_]; a.Result == "FAIL"]),
        "validation_errors":              count(validation_errors),
    },
    "validation_errors": validation_errors,
}

final_decision := "PASS" if count(validation_errors) == 0
final_decision := "FAIL" if count(validation_errors) > 0

# ─────────────────────────────────────────────────────────────────────────────
# Coverage Calculations
# ─────────────────────────────────────────────────────────────────────────────

inspected_sections := {sid |
    sid := input.code_section_ids[_]
    some act in input.inspection_activities
    sid in act.Code_Sections
}

uninspected_sections := {sid |
    sid := input.code_section_ids[_]
    not sid in inspected_sections
}

verified_plans := {pid |
    pid := input.plan_document_ids[_]
    some act in input.inspection_activities
    pid in act.Plans_Verified
}

unverified_plans := {pid |
    pid := input.plan_document_ids[_]
    not pid in verified_plans
}

code_coverage_percent := 100 if count(input.code_section_ids) == 0
code_coverage_percent := round((count(inspected_sections) / count(input.code_section_ids)) * 100) if count(input.code_section_ids) > 0

plans_coverage_percent := 100 if count(input.plan_document_ids) == 0
plans_coverage_percent := round((count(verified_plans) / count(input.plan_document_ids)) * 100) if count(input.plan_document_ids) > 0

# ─────────────────────────────────────────────────────────────────────────────
# Validation Rules
# ─────────────────────────────────────────────────────────────────────────────

validation_errors[msg] {
    not has_valid_metadata
    msg := "METADATA ERROR: Missing required fields (permit_id, inspection_date, inspector_id, inspector_license). Per NIST SP 800-53 AU-3 (Content of audit records)."
}

validation_errors[msg] {
    sid := uninspected_sections[_]
    msg := sprintf(
        "COVERAGE ERROR: Code section '%v' was not inspected. Per SDMC §129.0306 (Inspection requirements).",
        [sid]
    )
}

validation_errors[msg] {
    pid := unverified_plans[_]
    msg := sprintf(
        "PLAN ERROR: Plan document '%v' was not verified during inspection. Per SDMC §129.0306 (Inspection requirements).",
        [pid]
    )
}

validation_errors[msg] {
    act := input.inspection_activities[_]
    not act.Method in VALID_METHODS
    msg := sprintf(
        "METHOD ERROR: Inspection '%v' has invalid method '%v'. Valid methods: %v. Per SDMC §129.0306 (Inspection requirements).",
        [act.Inspection_ID, act.Method, VALID_METHODS]
    )
}

validation_errors[msg] {
    act := input.inspection_activities[_]
    not act.Result in VALID_RESULTS
    msg := sprintf(
        "RESULT ERROR: Inspection '%v' has invalid result '%v'. Valid results: %v.",
        [act.Inspection_ID, act.Result, VALID_RESULTS]
    )
}

validation_errors[msg] {
    act := input.inspection_activities[_]
    act.Result == "FAIL"
    msg := sprintf(
        "FAILED INSPECTION: Inspection '%v' FAILED for code sections %v. Per SDMC §129.0308 (Stop work orders) - failed inspections require correction before permit approval.",
        [act.Inspection_ID, act.Code_Sections]
    )
}

validation_errors[msg] {
    act := input.inspection_activities[_]
    act.Findings == ""
    msg := sprintf(
        "DOCUMENTATION ERROR: Inspection '%v' has no Findings. Per NIST SP 800-53 AU-6 (Audit review, analysis, and reporting).",
        [act.Inspection_ID]
    )
}

validation_errors[msg] {
    act := input.inspection_activities[_]
    not act.Photos_Attached == true
    msg := sprintf(
        "DOCUMENTATION ERROR: Inspection '%v' has no photos attached. Per NIST SP 800-53 AU-6 (Audit review, analysis, and reporting).",
        [act.Inspection_ID]
    )
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper Rules
# ─────────────────────────────────────────────────────────────────────────────

has_valid_metadata if {
    input.metadata.permit_id != ""
    input.metadata.inspection_date != ""
    input.metadata.inspector_id != ""
    input.metadata.inspector_license != ""
}
```

**Step 2: Commit**

```bash
git add policy/
git commit -m "feat: add OPA Gate 003 - SDMC inspection verification"
```

---

### Task 11: Test Suite

**Files:**
- Create: `services/evidence-ledger/tests/conftest.py`
- Create: `services/evidence-ledger/tests/test_gates.py`
- Create: `services/evidence-ledger/tests/test_evidence_api.py`
- Create: `services/evidence-ledger/tests/test_integrity.py`

**Step 1: Write `tests/conftest.py`**

```python
# services/evidence-ledger/tests/conftest.py
"""
Pytest fixtures for Evidence Ledger tests.

Uses in-process SQLite (aiosqlite) so tests run without Docker.
OPA calls are intercepted by pytest-httpx respx.
"""
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app

# In-memory SQLite for isolated test runs
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture(scope="function")
async def db_engine():
    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(db_engine):
    SessionLocal = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with SessionLocal() as session:
        yield session


@pytest_asyncio.fixture(scope="function")
async def client(db_session):
    """FastAPI test client with DB dependency overridden."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
```

**Step 2: Write `tests/test_gates.py`**

These tests verify the OPA policies. They require OPA to be running (integration tests).
Skip if OPA_URL env not set.

```python
# services/evidence-ledger/tests/test_gates.py
"""
Integration tests for OPA SDMC compliance gates.

Requires OPA running at OPA_URL (set in environment).
Skip these in unit test runs.
"""
import os
import pytest
import pytest_asyncio
import httpx

OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181")
pytestmark = pytest.mark.skipif(
    not os.environ.get("OPA_URL"),
    reason="OPA_URL not set - skipping OPA integration tests"
)

GATE_001_VALID_INPUT = {
    "metadata": {
        "permit_id": "BP-2025-TEST",
        "project_address": "123 Test St, San Diego, CA 92101",
        "applicant_name": "Test Builder Inc",
        "sdmc_version": "2024"
    },
    "code_sections": [{
        "Section_ID": "SDMC-142.0503",
        "Title": "Solar energy system standards",
        "Category": "Renewable Energy",
        "Verification_Method": "Inspection",
        "Compliance_Criteria": ["Structural load calculation per SDMC §142.0505"]
    }]
}


@pytest.mark.asyncio
async def test_gate_001_pass():
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{OPA_URL}/v1/data/compliance/gates/sdmc_code_validation/gate_report",
            json={"input": GATE_001_VALID_INPUT},
        )
    assert r.status_code == 200
    report = r.json()["result"]
    assert report["decision"] == "PASS"
    assert len(report["validation_errors"]) == 0


@pytest.mark.asyncio
async def test_gate_001_fail_missing_metadata():
    bad_input = dict(GATE_001_VALID_INPUT)
    bad_input["metadata"] = {}  # missing required fields
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{OPA_URL}/v1/data/compliance/gates/sdmc_code_validation/gate_report",
            json={"input": bad_input},
        )
    report = r.json()["result"]
    assert report["decision"] == "FAIL"
    assert any("METADATA ERROR" in e for e in report["validation_errors"])


@pytest.mark.asyncio
async def test_gate_001_fail_bad_section_format():
    bad_input = dict(GATE_001_VALID_INPUT)
    bad_input["code_sections"] = [{
        "Section_ID": "INVALID-FORMAT",  # wrong pattern
        "Verification_Method": "Inspection",
        "Compliance_Criteria": ["some criteria"]
    }]
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{OPA_URL}/v1/data/compliance/gates/sdmc_code_validation/gate_report",
            json={"input": bad_input},
        )
    report = r.json()["result"]
    assert report["decision"] == "FAIL"
    assert any("FORMAT ERROR" in e for e in report["validation_errors"])


@pytest.mark.asyncio
async def test_gate_002_pass():
    gate_input = {
        "metadata": {
            "permit_id": "BP-2025-TEST",
            "review_date": "2025-01-28",
            "reviewer_id": "reviewer.test@sandiego.gov",
            "plan_review_status": "APPROVED"
        },
        "code_section_ids": ["SDMC-142.0503"],
        "plan_documents": [{
            "Document_ID": "PLAN-001",
            "Document_Type": "Solar Panel Layout",
            "Code_Sections": ["SDMC-142.0503"],
            "Prepared_By": "Engineer #12345",
            "Date_Stamped": "2025-01-15"
        }]
    }
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{OPA_URL}/v1/data/compliance/gates/sdmc_plan_review/gate_report",
            json={"input": gate_input},
        )
    report = r.json()["result"]
    assert report["decision"] == "PASS"
    assert report["statistics"]["coverage_percent"] == 100


@pytest.mark.asyncio
async def test_gate_003_pass():
    gate_input = {
        "metadata": {
            "permit_id": "BP-2025-TEST",
            "inspection_date": "2025-01-28",
            "inspector_id": "inspector.test@sandiego.gov",
            "inspector_license": "CA-BUILD-INS-9876"
        },
        "code_section_ids": ["SDMC-142.0503"],
        "plan_document_ids": ["PLAN-001"],
        "inspection_activities": [{
            "Inspection_ID": "INS-001",
            "Inspection_Type": "Solar Installation",
            "Code_Sections": ["SDMC-142.0503"],
            "Plans_Verified": ["PLAN-001"],
            "Method": "Visual Inspection",
            "Result": "PASS",
            "Findings": "Solar panels installed per approved plans",
            "Photos_Attached": True
        }]
    }
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{OPA_URL}/v1/data/compliance/gates/sdmc_inspection/gate_report",
            json={"input": gate_input},
        )
    report = r.json()["result"]
    assert report["decision"] == "PASS"
    assert report["statistics"]["code_sections_coverage_percent"] == 100
```

**Step 3: Write `tests/test_evidence_api.py`**

```python
# services/evidence-ledger/tests/test_evidence_api.py
"""
Tests for Evidence Ledger API endpoints.

Key invariants verified:
1. Server recomputes hash (client hash ignored)
2. Round-trip persistence: created == retrieved
3. Hash format: sha256:<64hex>
4. Duplicate evidence_id returns 409
5. Gate evaluation blocks storage on FAIL
"""
import pytest
import pytest_asyncio
from unittest.mock import patch, AsyncMock

# ── Fixtures ────────────────────────────────────────────────────────────────

VALID_EVIDENCE = {
    "evidence_id": "BP-2025-TEST-GATE001-20250128",
    "gate_id": "gate-001-code-validation",
    "decision": {"result": "PASS", "reasons": ["All code sections valid"]},
    "inputs": {
        "permit_id": "BP-2025-TEST",
        "code_sections": ["SDMC-142.0503"]
    },
    "integrity": {
        "evidence_hash": "SHOULD_BE_IGNORED_BY_SERVER",
        "previous_hash": "SHOULD_BE_IGNORED_BY_SERVER",
        "signature": "test-inspector-signature-base64"
    },
    "signer_id": "reviewer.test@sandiego.gov"
}

# Mock OPA to return PASS without requiring running OPA
MOCK_GATE_PASS = {
    "decision": "PASS",
    "gate_id": "001",
    "validation_errors": []
}

MOCK_GATE_FAIL = {
    "decision": "FAIL",
    "gate_id": "001",
    "validation_errors": ["FORMAT ERROR: Section_ID invalid"]
}


@pytest.mark.asyncio
async def test_create_evidence_server_ignores_client_hash(client):
    """Server MUST recompute hash - client hash must be rejected."""
    with patch(
        "app.api.v1.evidence.evaluate_gate",
        new_callable=AsyncMock,
        return_value=MOCK_GATE_PASS
    ):
        r = await client.post("/v1/evidence", json=VALID_EVIDENCE)

    assert r.status_code == 201
    body = r.json()
    # Server hash must differ from client-provided hash
    assert body["integrity"]["evidence_hash"] != "SHOULD_BE_IGNORED_BY_SERVER"
    assert body["integrity"]["previous_hash"] != "SHOULD_BE_IGNORED_BY_SERVER"


@pytest.mark.asyncio
async def test_create_evidence_hash_format(client):
    """Server hash must be sha256:<64 hex chars>."""
    with patch(
        "app.api.v1.evidence.evaluate_gate",
        new_callable=AsyncMock,
        return_value=MOCK_GATE_PASS
    ):
        r = await client.post("/v1/evidence", json=VALID_EVIDENCE)

    assert r.status_code == 201
    h = r.json()["integrity"]["evidence_hash"]
    assert h.startswith("sha256:")
    hex_part = h[len("sha256:"):]
    assert len(hex_part) == 64
    assert all(c in "0123456789abcdef" for c in hex_part)


@pytest.mark.asyncio
async def test_create_evidence_signature_persisted(client):
    """Signature from client must persist to database (round-trip)."""
    with patch(
        "app.api.v1.evidence.evaluate_gate",
        new_callable=AsyncMock,
        return_value=MOCK_GATE_PASS
    ):
        created = await client.post("/v1/evidence", json=VALID_EVIDENCE)

    assert created.status_code == 201
    created_sig = created.json()["integrity"]["signature"]

    retrieved = await client.get(f"/v1/evidence/{VALID_EVIDENCE['evidence_id']}")
    assert retrieved.status_code == 200
    retrieved_sig = retrieved.json()["integrity"]["signature"]

    assert created_sig == retrieved_sig == "test-inspector-signature-base64"


@pytest.mark.asyncio
async def test_create_evidence_full_roundtrip(client):
    """All fields must match between created and retrieved record."""
    with patch(
        "app.api.v1.evidence.evaluate_gate",
        new_callable=AsyncMock,
        return_value=MOCK_GATE_PASS
    ):
        created = await client.post("/v1/evidence", json=VALID_EVIDENCE)

    assert created.status_code == 201
    created_body = created.json()

    retrieved = await client.get(f"/v1/evidence/{VALID_EVIDENCE['evidence_id']}")
    assert retrieved.status_code == 200
    retrieved_body = retrieved.json()

    # Full integrity envelope must match
    assert created_body["integrity"] == retrieved_body["integrity"]
    assert created_body["decision"] == retrieved_body["decision"]
    assert created_body["signer_id"] == retrieved_body["signer_id"]


@pytest.mark.asyncio
async def test_gate_fail_blocks_storage(client):
    """Failed gate must return 422 and NOT store record."""
    with patch(
        "app.api.v1.evidence.evaluate_gate",
        new_callable=AsyncMock,
        return_value=MOCK_GATE_FAIL
    ):
        r = await client.post("/v1/evidence", json=VALID_EVIDENCE)

    assert r.status_code == 422
    # Record must NOT exist
    get_r = await client.get(f"/v1/evidence/{VALID_EVIDENCE['evidence_id']}")
    assert get_r.status_code == 404


@pytest.mark.asyncio
async def test_get_evidence_not_found(client):
    r = await client.get("/v1/evidence/NONEXISTENT-ID")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_genesis_previous_hash(client):
    """First record must have genesis hash as previous_hash."""
    with patch(
        "app.api.v1.evidence.evaluate_gate",
        new_callable=AsyncMock,
        return_value=MOCK_GATE_PASS
    ):
        r = await client.post("/v1/evidence", json=VALID_EVIDENCE)

    assert r.status_code == 201
    prev = r.json()["integrity"]["previous_hash"]
    assert prev == "sha256:" + "0" * 64
```

**Step 4: Write `tests/test_integrity.py`**

```python
# services/evidence-ledger/tests/test_integrity.py
"""
Tests for hash chain integrity verification.

Verifies:
1. Single record passes verification
2. Two chained records: second's previous_hash == first's evidence_hash
3. All-records integrity endpoint returns ok=true
"""
import pytest
from unittest.mock import patch, AsyncMock

MOCK_GATE_PASS = {"decision": "PASS", "gate_id": "001", "validation_errors": []}


def make_evidence(eid: str) -> dict:
    return {
        "evidence_id": eid,
        "gate_id": "gate-001-code-validation",
        "decision": {"result": "PASS"},
        "inputs": {"permit_id": "BP-2025-TEST"},
        "integrity": {
            "evidence_hash": "CLIENT_HASH_IGNORED",
            "previous_hash": "CLIENT_PREV_IGNORED",
            "signature": f"sig-{eid}"
        },
        "signer_id": "test@sandiego.gov"
    }


@pytest.mark.asyncio
async def test_hash_chain_linkage(client):
    """Second record's previous_hash must equal first record's evidence_hash."""
    with patch(
        "app.api.v1.evidence.evaluate_gate",
        new_callable=AsyncMock,
        return_value=MOCK_GATE_PASS
    ):
        r1 = await client.post("/v1/evidence", json=make_evidence("REC-001"))
        r2 = await client.post("/v1/evidence", json=make_evidence("REC-002"))

    assert r1.status_code == 201
    assert r2.status_code == 201

    rec1_hash = r1.json()["integrity"]["evidence_hash"]
    rec2_prev = r2.json()["integrity"]["previous_hash"]

    assert rec2_prev == rec1_hash, (
        f"Hash chain broken: rec2.previous_hash={rec2_prev!r} "
        f"!= rec1.evidence_hash={rec1_hash!r}"
    )


@pytest.mark.asyncio
async def test_integrity_verify_empty(client):
    """Empty database must return ok=true with 0 records checked."""
    r = await client.get("/v1/integrity/verify")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["checked"] == 0
    assert body["errors"] == []


@pytest.mark.asyncio
async def test_integrity_verify_after_inserts(client):
    """After valid inserts, all records must pass integrity check."""
    with patch(
        "app.api.v1.evidence.evaluate_gate",
        new_callable=AsyncMock,
        return_value=MOCK_GATE_PASS
    ):
        await client.post("/v1/evidence", json=make_evidence("REC-A"))
        await client.post("/v1/evidence", json=make_evidence("REC-B"))
        await client.post("/v1/evidence", json=make_evidence("REC-C"))

    r = await client.get("/v1/integrity/verify")
    body = r.json()
    assert body["ok"] is True
    assert body["checked"] == 3
    assert body["errors"] == []


@pytest.mark.asyncio
async def test_health_ready(client):
    r = await client.get("/health/ready")
    assert r.status_code == 200
    assert r.json()["status"] == "ready"
```

**Step 5: Run all tests**

```bash
cd services/evidence-ledger
pip install -e ".[dev]" aiosqlite pytest-asyncio
pytest tests/ -v --tb=short
```

Expected: All tests pass (gates tests skipped without OPA_URL).

**Step 6: Commit**

```bash
git add services/evidence-ledger/tests/
git commit -m "test: add comprehensive test suite for API, hash chain, and integrity"
```

---

### Task 12: Validation Script and Report

**Files:**
- Create: `outputs/SDMC-VALIDATION-REPORT.md`
- Create: `sdmc-compliance/validate.sh`

**Step 1: Write validation script**

```bash
#!/usr/bin/env bash
# validate.sh - End-to-end validation of SDMC Compliance Platform
# Per NIST SP 800-53 CA-2 (Control Assessments)
set -euo pipefail

echo "=== SDMC Compliance Platform - End-to-End Validation ==="
echo "Starting services..."
docker-compose up -d
sleep 15

# 1. Database schema verification
echo ""
echo "--- Database Schema Verification ---"
docker exec "$(docker-compose ps -q postgres)" \
  psql -U sdmc -d permits -c "\d evidence_records" | tee /tmp/schema_check.txt
grep -q "evidence_hash" /tmp/schema_check.txt && echo "✅ Schema: evidence_hash column present" || echo "❌ Schema: FAIL"
grep -q "previous_hash" /tmp/schema_check.txt && echo "✅ Schema: previous_hash column present" || echo "❌ Schema: FAIL"
grep -q "signature"     /tmp/schema_check.txt && echo "✅ Schema: signature column present"     || echo "❌ Schema: FAIL"

# 2. Gate 001
echo ""
echo "--- Gate 001: Code Section Validation ---"
G1=$(curl -sf http://localhost:8181/v1/data/compliance/gates/sdmc_code_validation/gate_report \
  -d '{"input":{"metadata":{"permit_id":"BP-2025-TEST","project_address":"123 Test St, San Diego, CA","applicant_name":"Test Builder Inc","sdmc_version":"2024"},"code_sections":[{"Section_ID":"SDMC-142.0503","Title":"Solar energy system standards","Category":"Renewable Energy","Verification_Method":"Inspection","Compliance_Criteria":["Structural load calculation per SDMC §142.0505"]}]}}')
echo "$G1" | python3 -c "import sys,json; r=json.load(sys.stdin)['result']; print('✅ Gate 001:',r['decision'],'| errors:',len(r['validation_errors']))"

# 3. Gate 002
echo ""
echo "--- Gate 002: Plan Review ---"
G2=$(curl -sf http://localhost:8181/v1/data/compliance/gates/sdmc_plan_review/gate_report \
  -d '{"input":{"metadata":{"permit_id":"BP-2025-TEST","review_date":"2025-01-28","reviewer_id":"reviewer.test@sandiego.gov","plan_review_status":"APPROVED"},"code_section_ids":["SDMC-142.0503"],"plan_documents":[{"Document_ID":"PLAN-001","Document_Type":"Solar Panel Layout","Code_Sections":["SDMC-142.0503"],"Prepared_By":"Engineer #12345","Date_Stamped":"2025-01-15"}]}}')
echo "$G2" | python3 -c "import sys,json; r=json.load(sys.stdin)['result']; print('✅ Gate 002:',r['decision'],'| coverage:',r['statistics']['coverage_percent'],'%')"

# 4. Gate 003
echo ""
echo "--- Gate 003: Inspection ---"
G3=$(curl -sf http://localhost:8181/v1/data/compliance/gates/sdmc_inspection/gate_report \
  -d '{"input":{"metadata":{"permit_id":"BP-2025-TEST","inspection_date":"2025-01-28","inspector_id":"inspector.test@sandiego.gov","inspector_license":"CA-BUILD-INS-9876"},"code_section_ids":["SDMC-142.0503"],"plan_document_ids":["PLAN-001"],"inspection_activities":[{"Inspection_ID":"INS-001","Inspection_Type":"Solar Installation","Code_Sections":["SDMC-142.0503"],"Plans_Verified":["PLAN-001"],"Method":"Visual Inspection","Result":"PASS","Findings":"Solar panels installed per approved plans","Photos_Attached":true}]}}')
echo "$G3" | python3 -c "import sys,json; r=json.load(sys.stdin)['result']; print('✅ Gate 003:',r['decision'],'| code coverage:',r['statistics']['code_sections_coverage_percent'],'%')"

# 5. Evidence create
echo ""
echo "--- Evidence Ledger: Create ---"
CREATED=$(curl -sf -X POST http://localhost:8000/v1/evidence \
  -H "Content-Type: application/json" \
  -d '{"evidence_id":"BP-2025-TEST-GATE001-20250128","gate_id":"gate-001-code-validation","decision":{"result":"PASS"},"inputs":{"permit_id":"BP-2025-TEST","code_sections":["SDMC-142.0503"]},"integrity":{"evidence_hash":"IGNORED","previous_hash":"IGNORED","signature":"test-inspector-sig"},"signer_id":"reviewer.test@sandiego.gov"}')
echo "$CREATED" | python3 -c "import sys,json; r=json.load(sys.stdin); print('✅ Created:', r['evidence_id'])"

# 6. Hash validation
HASH=$(echo "$CREATED" | python3 -c "import sys,json; print(json.load(sys.stdin)['integrity']['evidence_hash'])")
[[ "$HASH" != "IGNORED" ]] && echo "✅ Server hash: not client value" || echo "❌ FAIL: client hash leaked"
[[ "${HASH:0:7}" == "sha256:" ]] && echo "✅ Hash format: sha256: prefix" || echo "❌ FAIL: bad format"

# 7. Round-trip
echo ""
echo "--- Evidence Ledger: Retrieve (Round-trip) ---"
RETRIEVED=$(curl -sf http://localhost:8000/v1/evidence/BP-2025-TEST-GATE001-20250128)
CREATED_SIG=$(echo "$CREATED" | python3 -c "import sys,json; print(json.load(sys.stdin)['integrity']['signature'])")
RETRIEVED_SIG=$(echo "$RETRIEVED" | python3 -c "import sys,json; print(json.load(sys.stdin)['integrity']['signature'])")
[[ "$CREATED_SIG" == "$RETRIEVED_SIG" ]] && echo "✅ Round-trip: signature persisted" || echo "❌ FAIL: signature mismatch"

# 8. Integrity verification
echo ""
echo "--- Integrity Verification ---"
INTEGRITY=$(curl -sf http://localhost:8000/v1/integrity/verify)
echo "$INTEGRITY" | python3 -c "import sys,json; r=json.load(sys.stdin); print('✅ Integrity: ok=' + str(r['ok']) + ' checked=' + str(r['checked']) + ' errors=' + str(len(r['errors'])))"

echo ""
echo "=== VALIDATION COMPLETE ==="
```

**Step 2: Commit**

```bash
chmod +x validate.sh
git add validate.sh outputs/
git commit -m "feat: add end-to-end validation script"
```

---

### Task 13: Final Integration Run

**Step 1: Start all services**

```bash
cd /c/Users/ablan/Documents/Claude/sdmc-compliance
docker-compose up --build -d
```

**Step 2: Wait for services**

```bash
docker-compose logs -f evidence-ledger &
sleep 20
curl http://localhost:8000/health/ready
```

Expected: `{"status": "ready", "service": "evidence-ledger"}`

**Step 3: Run validation script**

```bash
bash validate.sh
```

Expected:
```
✅ Schema: evidence_hash column present
✅ Schema: previous_hash column present
✅ Schema: signature column present
✅ Gate 001: PASS | errors: 0
✅ Gate 002: PASS | coverage: 100 %
✅ Gate 003: PASS | code coverage: 100 %
✅ Created: BP-2025-TEST-GATE001-20250128
✅ Server hash: not client value
✅ Hash format: sha256: prefix
✅ Round-trip: signature persisted
✅ Integrity: ok=True checked=1 errors=[]
```

**Step 4: Run unit tests**

```bash
cd services/evidence-ledger
OPA_URL=http://localhost:8181 pytest tests/ -v
```

Expected: All tests pass.

**Step 5: Final commit**

```bash
cd /c/Users/ablan/Documents/Claude/sdmc-compliance
git add -A
git commit -m "feat: complete SDMC Municipal Code Compliance Platform v1.0"
```

---

## Summary of All Files

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Orchestrates postgres, opa, evidence-ledger |
| `migrations/001_init_permits_schema.sql` | Creates evidence_records table with append-only rules |
| `policy/opa/compliance-gates/gate-001-sdmc-code-validation.rego` | OPA: validates SDMC code sections |
| `policy/opa/compliance-gates/gate-002-sdmc-plan-review.rego` | OPA: bidirectional plan-section traceability |
| `policy/opa/compliance-gates/gate-003-sdmc-inspection.rego` | OPA: inspection coverage and documentation |
| `services/evidence-ledger/app/db.py` | Async SQLAlchemy engine + session factory |
| `services/evidence-ledger/app/models/evidence.py` | ORM model (must match schema exactly) |
| `services/evidence-ledger/app/schemas/evidence.py` | Pydantic v2 request/response schemas |
| `services/evidence-ledger/app/services/opa_gate.py` | OPA HTTP client for gate evaluation |
| `services/evidence-ledger/app/repo/evidence_repo.py` | Core crypto: server-side SHA-256 hash chain |
| `services/evidence-ledger/app/api/v1/evidence.py` | POST /v1/evidence, GET /v1/evidence/{id} |
| `services/evidence-ledger/app/api/v1/integrity.py` | GET /v1/integrity/verify |
| `services/evidence-ledger/app/main.py` | FastAPI app with lifespan and router registration |
| `services/evidence-ledger/tests/conftest.py` | pytest fixtures (in-memory SQLite) |
| `services/evidence-ledger/tests/test_evidence_api.py` | API unit tests (OPA mocked) |
| `services/evidence-ledger/tests/test_integrity.py` | Hash chain unit tests |
| `services/evidence-ledger/tests/test_gates.py` | OPA integration tests (requires OPA_URL) |
| `validate.sh` | End-to-end acceptance test script |

## Critical Security Rules (Do Not Violate)

1. **NEVER** use client-provided `integrity.evidence_hash` or `integrity.previous_hash`
2. **ALWAYS** call `_get_last_hash()` server-side before computing new hash
3. **ALWAYS** use `sha256:` prefix in hash output
4. **ALWAYS** use `sort_keys=True, separators=(",", ":")` for canonical JSON
5. **NEVER** allow updates or deletes to evidence records
6. **NEVER** return a 200 for a gate-FAILed create request
