"""
Tests for GET /v1/integrity/verify and the EvidenceRepo hash chain logic.

Records are created via EvidenceRepo directly (bypassing the API and OPA)
so that chain-property tests remain focused on the cryptographic logic and
don't require mocking.  Tampering tests exploit the fact that SQLite in-memory
does NOT enforce the append-only SQL RULE from the Postgres migration —
allowing deliberate corruption to verify the chain-break detection.

Per NIST SP 800-53 AU-9 (Protection of Audit Information)
Per 21 CFR Part 11 §11.10(a) (System Validation)
"""
from sqlalchemy import update

from app.models.evidence import EvidenceRecord
from app.repo.evidence_repo import GENESIS_HASH, EvidenceRepo
from app.schemas.evidence import EvidenceCreate, IntegrityIn

# ── Helpers ────────────────────────────────────────────────────────────────


def _make_create(
    evidence_id: str,
    gate_id: str = "gate-001-code-validation",
) -> EvidenceCreate:
    """Build a minimal EvidenceCreate for direct repository use (no API)."""
    return EvidenceCreate(
        evidence_id=evidence_id,
        gate_id=gate_id,
        decision={
            "decision": "PASS",
            "gate_id": "001",
            "validation_errors": [],
            "timestamp": 1741305600000,
        },
        inputs={
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
                    "Compliance_Criteria": ["Structural load requirements"],
                }
            ],
        },
        integrity=IntegrityIn(
            evidence_hash="client-ignored",
            previous_hash="client-ignored",
            signature="sig-placeholder",
        ),
        signer_id="inspector@sandiego.gov",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint: GET /v1/integrity/verify
# ─────────────────────────────────────────────────────────────────────────────


class TestIntegrityVerifyEndpoint:
    """Tests for the GET /v1/integrity/verify HTTP endpoint."""

    async def test_empty_chain_ok_checked_zero(self, api_client):
        """
        Empty evidence_records table → ok=True, checked=0, errors=[].

        Vacuously true: a chain with no records has no violations.
        """
        response = await api_client.get("/v1/integrity/verify")

        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True
        assert data["checked"] == 0
        assert data["errors"] == []

    async def test_single_valid_record_ok(self, db_session, api_client):
        """Single correctly hashed record → ok=True, checked=1, errors=[]."""
        repo = EvidenceRepo(db_session)
        await repo.create(_make_create("BP-2026-00001-GATE001-20260307"))

        response = await api_client.get("/v1/integrity/verify")

        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True
        assert data["checked"] == 1
        assert data["errors"] == []

    async def test_two_valid_chained_records_ok(self, db_session, api_client):
        """Two correctly chained records → ok=True, checked=2, errors=[]."""
        repo = EvidenceRepo(db_session)
        await repo.create(_make_create("BP-2026-00001-GATE001-20260307"))
        await repo.create(_make_create("BP-2026-00002-GATE001-20260307"))

        response = await api_client.get("/v1/integrity/verify")

        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True
        assert data["checked"] == 2
        assert data["errors"] == []

    async def test_tampered_evidence_hash_detected(self, db_session, api_client):
        """
        Corrupted evidence_hash → ok=False, errors include the record id.

        Simulates a direct database modification bypassing the API
        (possible if a DB admin had raw access).
        Per NIST SP 800-53 AU-9: detect tampering at verification time.
        """
        repo = EvidenceRepo(db_session)
        record = await repo.create(_make_create("BP-2026-00001-GATE001-20260307"))

        # Tamper: replace stored hash with a fraudulent value
        await db_session.execute(
            update(EvidenceRecord)
            .where(EvidenceRecord.evidence_id == record.evidence_id)
            .values(evidence_hash="sha256:" + "a" * 64)
        )
        await db_session.commit()

        response = await api_client.get("/v1/integrity/verify")

        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is False
        assert data["checked"] == 1
        assert any(record.evidence_id in e for e in data["errors"])

    async def test_tampered_previous_hash_chain_break_detected(
        self, db_session, api_client
    ):
        """
        Corrupted previous_hash on record 2 → chain break detected.

        Even if both evidence_hashes are internally consistent, a wrong
        previous_hash breaks the linking between records.
        Per 21 CFR Part 11 §11.10(e): sequential ordering must be verifiable.
        """
        repo = EvidenceRepo(db_session)
        await repo.create(_make_create("BP-2026-00001-GATE001-20260307"))
        record2 = await repo.create(_make_create("BP-2026-00002-GATE001-20260307"))

        # Tamper: corrupt the previous_hash linkage on record 2
        await db_session.execute(
            update(EvidenceRecord)
            .where(EvidenceRecord.evidence_id == record2.evidence_id)
            .values(previous_hash="sha256:" + "b" * 64)
        )
        await db_session.commit()

        response = await api_client.get("/v1/integrity/verify")

        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is False
        assert any(record2.evidence_id in e for e in data["errors"])

    async def test_checked_count_matches_records_in_db(self, db_session, api_client):
        """checked count in response equals the number of records in the DB."""
        repo = EvidenceRepo(db_session)
        n = 3
        for i in range(1, n + 1):
            await repo.create(_make_create(f"BP-2026-{i:05d}-GATE001-20260307"))

        response = await api_client.get("/v1/integrity/verify")

        assert response.json()["checked"] == n


# ─────────────────────────────────────────────────────────────────────────────
# EvidenceRepo hash chain unit tests (no HTTP layer)
# ─────────────────────────────────────────────────────────────────────────────


class TestHashChainProperties:
    """
    White-box tests for the EvidenceRepo hash-chain logic.

    These tests call EvidenceRepo methods directly, verifying the
    cryptographic invariants without going through the HTTP layer.
    """

    async def test_genesis_hash_format(self):
        """GENESIS_HASH must be 'sha256:' followed by exactly 64 hex zeros."""
        assert GENESIS_HASH.startswith("sha256:")
        hex_part = GENESIS_HASH[len("sha256:"):]
        assert len(hex_part) == 64
        assert all(c == "0" for c in hex_part)

    async def test_first_record_previous_hash_is_genesis(self, db_session):
        """First record created must have previous_hash == GENESIS_HASH."""
        repo = EvidenceRepo(db_session)
        record = await repo.create(_make_create("BP-2026-00001-GATE001-20260307"))

        assert record.previous_hash == GENESIS_HASH

    async def test_evidence_hash_has_sha256_prefix(self, db_session):
        """evidence_hash must start with 'sha256:' followed by 64 hex chars."""
        repo = EvidenceRepo(db_session)
        record = await repo.create(_make_create("BP-2026-00001-GATE001-20260307"))

        assert record.evidence_hash.startswith("sha256:")
        hex_part = record.evidence_hash[len("sha256:"):]
        assert len(hex_part) == 64
        assert all(c in "0123456789abcdef" for c in hex_part)

    async def test_different_inputs_produce_different_hashes(self, db_session):
        """Two records with different evidence_ids must have different hashes."""
        repo = EvidenceRepo(db_session)
        r1 = await repo.create(_make_create("BP-2026-00001-GATE001-20260307"))
        r2 = await repo.create(_make_create("BP-2026-00002-GATE001-20260307"))

        assert r1.evidence_hash != r2.evidence_hash

    async def test_chain_linkage_record2_points_to_record1(self, db_session):
        """Record 2's previous_hash must equal Record 1's evidence_hash."""
        repo = EvidenceRepo(db_session)
        r1 = await repo.create(_make_create("BP-2026-00001-GATE001-20260307"))
        r2 = await repo.create(_make_create("BP-2026-00002-GATE001-20260307"))

        assert r2.previous_hash == r1.evidence_hash

    async def test_verify_chain_returns_tuple_of_three(self, db_session):
        """verify_chain() returns (ok: bool, checked: int, errors: list[str])."""
        repo = EvidenceRepo(db_session)
        result = await repo.verify_chain()

        assert isinstance(result, tuple)
        assert len(result) == 3
        ok, checked, errors = result
        assert isinstance(ok, bool)
        assert isinstance(checked, int)
        assert isinstance(errors, list)

    async def test_verify_chain_empty_db(self, db_session):
        """verify_chain() on empty DB returns (True, 0, [])."""
        repo = EvidenceRepo(db_session)
        ok, checked, errors = await repo.verify_chain()

        assert ok is True
        assert checked == 0
        assert errors == []

    async def test_verify_chain_passes_for_valid_records(self, db_session):
        """verify_chain() returns ok=True for legitimately created records."""
        repo = EvidenceRepo(db_session)
        await repo.create(_make_create("BP-2026-00001-GATE001-20260307"))
        await repo.create(_make_create("BP-2026-00002-GATE001-20260307"))

        ok, checked, errors = await repo.verify_chain()

        assert ok is True
        assert checked == 2
        assert errors == []

    async def test_verify_chain_detects_corrupted_hash(self, db_session):
        """verify_chain() returns ok=False when a stored hash is corrupted."""
        repo = EvidenceRepo(db_session)
        record = await repo.create(_make_create("BP-2026-00001-GATE001-20260307"))

        # Direct DB corruption bypasses the append-only enforcement
        await db_session.execute(
            update(EvidenceRecord)
            .where(EvidenceRecord.evidence_id == record.evidence_id)
            .values(evidence_hash="sha256:" + "c" * 64)
        )
        await db_session.commit()

        ok, checked, errors = await repo.verify_chain()

        assert ok is False
        assert checked == 1
        assert len(errors) > 0

    async def test_compute_hash_is_deterministic(self):
        """
        _compute_hash() is deterministic: same inputs always produce same hash.

        Per NIST SP 800-53 SC-13: cryptographic operations must be repeatable.
        """
        # We test this by instantiating a repo with None session (hash compute
        # doesn't use the session)
        from app.repo.evidence_repo import EvidenceRepo as Repo

        repo = Repo(db=None)  # type: ignore[arg-type]
        h1 = repo._compute_hash("id1", "gate-001", '{"a":1}', '{"b":2}', GENESIS_HASH)
        h2 = repo._compute_hash("id1", "gate-001", '{"a":1}', '{"b":2}', GENESIS_HASH)

        assert h1 == h2
        assert h1.startswith("sha256:")

    async def test_compute_hash_changes_with_different_previous(self):
        """
        Changing previous_hash input changes the resulting hash.

        Ensures the chain link is cryptographically bound — you cannot
        reorder records without changing all downstream hashes.
        """
        repo = EvidenceRepo(db=None)  # type: ignore[arg-type]
        h1 = repo._compute_hash("id1", "gate-001", '{"a":1}', '{"b":2}', GENESIS_HASH)
        h2 = repo._compute_hash("id1", "gate-001", '{"a":1}', '{"b":2}', "sha256:" + "1" * 64)

        assert h1 != h2

    async def test_canonical_json_is_sort_keys_deterministic(self):
        """
        _canonical_json produces the same string regardless of dict insertion order.

        Per NIST SP 800-53 SC-13: deterministic hashing requirement.
        """
        repo = EvidenceRepo(db=None)  # type: ignore[arg-type]
        d1 = {"b": 2, "a": 1, "c": {"z": 26, "m": 13}}
        d2 = {"a": 1, "c": {"m": 13, "z": 26}, "b": 2}

        assert repo._canonical_json(d1) == repo._canonical_json(d2)

    async def test_canonical_json_no_whitespace(self):
        """
        _canonical_json uses compact separators (no spaces) for minimal, deterministic output.
        """
        repo = EvidenceRepo(db=None)  # type: ignore[arg-type]
        result = repo._canonical_json({"key": "value"})

        assert " " not in result
        assert result == '{"key":"value"}'
