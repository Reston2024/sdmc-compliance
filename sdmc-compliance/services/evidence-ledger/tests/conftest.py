"""
Shared pytest fixtures for SDMC Evidence Ledger test suite.

Uses in-memory SQLite (aiosqlite) so tests run without Docker or a live
Postgres instance.  pytest-asyncio asyncio_mode="auto" (set in pyproject.toml)
means every async function in a test module is automatically collected as a
coroutine — no @pytest.mark.asyncio decorator needed.

Per NIST SP 800-53 SA-11 (Developer Testing and Evaluation)
"""
# IMPORTANT: Set DATABASE_URL *before* any app module is imported.
# app/db.py creates the SQLAlchemy engine at module-load time using this env
# var.  If it is not overridden here, the default postgresql+asyncpg:// URL
# is used, which requires asyncpg and a live Postgres server.
import os
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

import pytest
import pytest_asyncio
import httpx
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

# Import app artefacts — models must be imported before create_all so that
# Base.metadata knows about the evidence_records table.
import app.models.evidence  # noqa: F401  (registers EvidenceRecord on Base)
from app.db import Base, get_db
from app.main import app

# SQLite in-memory URL — no files, no Docker, isolated per test function
TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


# ─────────────────────────────────────────────────────────────────────────────
# Database fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def db_engine():
    """
    In-memory SQLite engine with schema created via ORM metadata.

    A fresh engine is created for every test function (default fixture scope),
    guaranteeing full isolation between tests.

    NOTE: SQLite compatible notes
    - JSONB columns are created as 'JSONB' type name; SQLite uses type
      affinity rules (TEXT) and SQLAlchemy handles serialisation transparently.
    - The GIN index postgresql_using='gin' kwarg is ignored by SQLite dialect.
    - SELECT FOR UPDATE in _get_last_hash() is silently ignored by SQLite;
      concurrency safety is tested implicitly in Docker integration runs.
    - CURRENT_TIMESTAMP server_default (ISO SQL) works on both SQLite and PG.
    """
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine):
    """
    Async SQLAlchemy session wired to the in-memory test engine.

    expire_on_commit=False lets tests read back attributes after the
    EvidenceRepo.create() commit without issuing extra SELECTs.
    """
    factory = async_sessionmaker(
        db_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as session:
        yield session


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI test client fixture
# ─────────────────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def api_client(db_session):
    """
    Async httpx client pointed at the FastAPI app with the test DB injected.

    ASGITransport sends 'http' scopes only — the lifespan startup hook
    (which does SELECT 1 against the real Postgres engine) is NOT triggered,
    so no monkeypatching of the engine is required.

    get_db is overridden with a dependency that yields the test db_session,
    ensuring all route handlers hit the same in-memory SQLite instance.
    """
    async def _override_get_db() -> AsyncSession:
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as client:
        yield client

    app.dependency_overrides.clear()


# ─────────────────────────────────────────────────────────────────────────────
# Shared test-data factory
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def make_body():
    """
    Returns a factory function that builds minimal valid EvidenceCreate bodies.

    Usage in tests::

        async def test_foo(api_client, make_body):
            body = make_body()                          # defaults
            body2 = make_body(evidence_id="BP-2026-99") # custom id

    The fake_hash is intentionally wrong to verify the server ignores it.
    """
    def _factory(
        evidence_id: str = "BP-2026-00001-GATE001-20260307",
        gate_id: str = "gate-001-code-validation",
        fake_hash: str = "client-provided-hash-must-be-ignored",
    ) -> dict:
        return {
            "evidence_id": evidence_id,
            "gate_id": gate_id,
            "decision": {
                "decision": "PASS",
                "gate_id": "001",
                "gate_name": "Code Section Validation",
                "validation_errors": [],
                "timestamp": 1741305600000,
            },
            "inputs": {
                "metadata": {
                    "permit_id": "BP-2026-00001",
                    "project_address": "123 Main St, San Diego CA 92101",
                    "applicant_name": "Jane Engineer PE #12345",
                    "sdmc_version": "2024",
                },
                "code_sections": [
                    {
                        "Section_ID": "SDMC-142.0503",
                        "Verification_Method": "Inspection",
                        "Compliance_Criteria": [
                            "Structural load requirements per SDMC §142.0503"
                        ],
                    }
                ],
            },
            "integrity": {
                "evidence_hash": fake_hash,
                "previous_hash": "client-provided-previous-also-ignored",
                "signature": "sig-placeholder-base64",
            },
            "signer_id": "inspector@sandiego.gov",
        }

    return _factory
