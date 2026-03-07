"""
Integration tests for the evidence record API endpoints.

  POST /v1/evidence      – create an evidence record after gate validation
  GET  /v1/evidence/{id} – retrieve a single evidence record

evaluate_gate() is patched with unittest.mock.AsyncMock so these tests run
without a live OPA instance.  The DB is in-memory SQLite (via conftest).

Per NIST SP 800-53 SA-11 (Developer Testing and Evaluation)
Per 21 CFR Part 11 §11.10(a) (System Validation)
"""
import re
from unittest.mock import AsyncMock, patch

import pytest

from app.repo.evidence_repo import GENESIS_HASH

# ── Constants ──────────────────────────────────────────────────────────────

MOCK_TARGET = "app.api.v1.evidence.evaluate_gate"

SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")

GATE_PASS_REPORT = {
    "decision": "PASS",
    "gate_id": "001",
    "gate_name": "Code Section Validation",
    "sections_evaluated": 1,
    "sections_passed": 1,
    "validation_errors": [],
    "timestamp": 1741305600000,
}

GATE_FAIL_REPORT = {
    "decision": "FAIL",
    "gate_id": "001",
    "gate_name": "Code Section Validation",
    "validation_errors": [
        "FORMAT ERROR: Section_ID 'BADID' does not match SDMC-###.####. Per SDMC §129.0302."
    ],
    "timestamp": 1741305600000,
}


# ─────────────────────────────────────────────────────────────────────────────
# POST /v1/evidence
# ─────────────────────────────────────────────────────────────────────────────


class TestCreateEvidence:
    """Tests for POST /v1/evidence."""

    async def test_gate_pass_returns_201_with_evidence_record(
        self, api_client, make_body
    ):
        """Gate PASS → 201 Created with EvidenceResponse body."""
        body = make_body()

        with patch(MOCK_TARGET, new_callable=AsyncMock) as mock_gate:
            mock_gate.return_value = GATE_PASS_REPORT
            response = await api_client.post("/v1/evidence", json=body)

        assert response.status_code == 201
        data = response.json()
        assert data["evidence_id"] == body["evidence_id"]
        assert data["gate_id"] == body["gate_id"]
        assert data["signer_id"] == body["signer_id"]
        assert "integrity" in data
        assert "created_at" in data

    async def test_server_computes_sha256_hash_with_prefix(
        self, api_client, make_body
    ):
        """
        Server MUST return evidence_hash matching sha256:<64hex>.

        This is the 21 CFR Part 11 §11.10(a) integrity control — the system
        itself computes the hash, never the client.
        Per NIST SP 800-53 SC-13 (Cryptographic Protection / FIPS 140-2).
        """
        body = make_body(fake_hash="THIS-FAKE-HASH-MUST-NEVER-APPEAR")

        with patch(MOCK_TARGET, new_callable=AsyncMock) as mock_gate:
            mock_gate.return_value = GATE_PASS_REPORT
            response = await api_client.post("/v1/evidence", json=body)

        assert response.status_code == 201
        actual_hash = response.json()["integrity"]["evidence_hash"]
        assert SHA256_RE.match(actual_hash), (
            f"evidence_hash '{actual_hash}' must match sha256:<64hex>"
        )

    async def test_client_provided_hash_is_ignored(self, api_client, make_body):
        """
        Client's integrity.evidence_hash value MUST be ignored.

        Security invariant: client cannot supply its own hash.
        Per NIST SP 800-53 AC-3 (Access Enforcement).
        """
        fake = "THIS-FAKE-HASH-MUST-NEVER-APPEAR"
        body = make_body(fake_hash=fake)

        with patch(MOCK_TARGET, new_callable=AsyncMock) as mock_gate:
            mock_gate.return_value = GATE_PASS_REPORT
            response = await api_client.post("/v1/evidence", json=body)

        assert response.status_code == 201
        assert response.json()["integrity"]["evidence_hash"] != fake

    async def test_client_provided_previous_hash_is_ignored(
        self, api_client, make_body
    ):
        """
        Client's integrity.previous_hash value MUST be ignored.

        The server chains to the ACTUAL last stored record, not to whatever
        the client claims.  Per 21 CFR Part 11 §11.10(e) (Sequential ordering).
        """
        body = make_body()
        body["integrity"]["previous_hash"] = "totally-made-up-previous"

        with patch(MOCK_TARGET, new_callable=AsyncMock) as mock_gate:
            mock_gate.return_value = GATE_PASS_REPORT
            response = await api_client.post("/v1/evidence", json=body)

        assert response.status_code == 201
        assert response.json()["integrity"]["previous_hash"] != "totally-made-up-previous"

    async def test_first_record_previous_hash_equals_genesis(
        self, api_client, make_body
    ):
        """
        First record's previous_hash MUST equal GENESIS_HASH.

        Per 21 CFR Part 11 §11.10(e): hash chain starts from a known genesis.
        """
        body = make_body()

        with patch(MOCK_TARGET, new_callable=AsyncMock) as mock_gate:
            mock_gate.return_value = GATE_PASS_REPORT
            response = await api_client.post("/v1/evidence", json=body)

        assert response.status_code == 201
        assert response.json()["integrity"]["previous_hash"] == GENESIS_HASH

    async def test_second_record_chains_to_first(self, api_client, make_body):
        """
        Second record's previous_hash MUST equal first record's evidence_hash.

        Verifies the cryptographic chain: each record links back to its
        predecessor.  Per 21 CFR Part 11 §11.10(e).
        """
        body1 = make_body(evidence_id="BP-2026-00001-GATE001-20260307")
        body2 = make_body(evidence_id="BP-2026-00002-GATE001-20260307")

        with patch(MOCK_TARGET, new_callable=AsyncMock) as mock_gate:
            mock_gate.return_value = GATE_PASS_REPORT
            r1 = await api_client.post("/v1/evidence", json=body1)
            r2 = await api_client.post("/v1/evidence", json=body2)

        assert r1.status_code == 201
        assert r2.status_code == 201
        hash1 = r1.json()["integrity"]["evidence_hash"]
        prev2 = r2.json()["integrity"]["previous_hash"]
        assert prev2 == hash1, (
            f"Record 2 previous_hash {prev2!r} must equal Record 1 hash {hash1!r}"
        )

    async def test_client_signature_stored_as_provided(self, api_client, make_body):
        """
        Client's integrity.signature MUST be stored and returned as-is.

        Unlike evidence_hash/previous_hash, the signature is a client-supplied
        attestation that is passed through unchanged.
        Per NIST SP 800-53 IA-2 and 21 CFR Part 11 §11.50.
        """
        body = make_body()
        body["integrity"]["signature"] = "official-sig-base64-abc123"

        with patch(MOCK_TARGET, new_callable=AsyncMock) as mock_gate:
            mock_gate.return_value = GATE_PASS_REPORT
            response = await api_client.post("/v1/evidence", json=body)

        assert response.status_code == 201
        assert response.json()["integrity"]["signature"] == "official-sig-base64-abc123"

    async def test_decision_and_inputs_stored_correctly(self, api_client, make_body):
        """Decision dict and inputs dict are stored and returned verbatim."""
        body = make_body()

        with patch(MOCK_TARGET, new_callable=AsyncMock) as mock_gate:
            mock_gate.return_value = GATE_PASS_REPORT
            response = await api_client.post("/v1/evidence", json=body)

        assert response.status_code == 201
        data = response.json()
        assert data["decision"] == body["decision"]
        assert data["inputs"] == body["inputs"]

    async def test_gate_fail_returns_422_not_stored(self, api_client, make_body):
        """
        Gate FAIL → 422 Unprocessable Entity.  Evidence NOT stored.

        Per SDMC §129.0302: gate must pass before permit evidence is recorded.
        """
        body = make_body()

        with patch(MOCK_TARGET, new_callable=AsyncMock) as mock_gate:
            mock_gate.return_value = GATE_FAIL_REPORT
            post_resp = await api_client.post("/v1/evidence", json=body)

        assert post_resp.status_code == 422
        detail = post_resp.json()["detail"]
        assert detail["decision"] == "FAIL"
        assert len(detail["validation_errors"]) > 0

        # Verify record was NOT stored
        get_resp = await api_client.get(f"/v1/evidence/{body['evidence_id']}")
        assert get_resp.status_code == 404

    async def test_unknown_gate_id_returns_400(self, api_client, make_body):
        """
        Unknown gate_id → 400 Bad Request.

        evaluate_gate raises ValueError for unrecognised gates.
        Per SDMC §129.0302: only valid gates are accepted.
        """
        body = make_body(gate_id="gate-999-does-not-exist")

        with patch(
            MOCK_TARGET,
            side_effect=ValueError("Unknown gate_id 'gate-999-does-not-exist'"),
        ):
            response = await api_client.post("/v1/evidence", json=body)

        assert response.status_code == 400
        assert "gate-999-does-not-exist" in response.json()["detail"]

    async def test_opa_unavailable_returns_503(self, api_client, make_body):
        """
        OPA communication failure → 503 Service Unavailable.

        Per NIST SP 800-53 SA-9: dependent service failure must not silently
        allow evidence to be stored.
        """
        import httpx as httpx_lib

        body = make_body()

        with patch(
            MOCK_TARGET,
            side_effect=httpx_lib.ConnectError("Connection refused"),
        ):
            response = await api_client.post("/v1/evidence", json=body)

        assert response.status_code == 503
        assert "OPA policy evaluation failed" in response.json()["detail"]

    async def test_duplicate_evidence_id_returns_error(self, api_client, make_body):
        """
        Duplicate evidence_id (PK violation) must not silently succeed.

        evidence_records.evidence_id is a TEXT PRIMARY KEY — the DB rejects
        duplicate inserts.
        """
        body = make_body()

        with patch(MOCK_TARGET, new_callable=AsyncMock) as mock_gate:
            mock_gate.return_value = GATE_PASS_REPORT
            r1 = await api_client.post("/v1/evidence", json=body)
            assert r1.status_code == 201

            # Second insert with SAME evidence_id
            r2 = await api_client.post("/v1/evidence", json=body)

        # SQLite UNIQUE constraint violation propagates as a 500 or 422
        assert r2.status_code in (409, 422, 500)


# ─────────────────────────────────────────────────────────────────────────────
# GET /v1/evidence/{evidence_id}
# ─────────────────────────────────────────────────────────────────────────────


class TestGetEvidence:
    """Tests for GET /v1/evidence/{evidence_id}."""

    async def test_get_existing_record_returns_200(self, api_client, make_body):
        """GET an existing record returns 200 with the full EvidenceResponse."""
        body = make_body()

        with patch(MOCK_TARGET, new_callable=AsyncMock) as mock_gate:
            mock_gate.return_value = GATE_PASS_REPORT
            create_resp = await api_client.post("/v1/evidence", json=body)

        assert create_resp.status_code == 201

        get_resp = await api_client.get(f"/v1/evidence/{body['evidence_id']}")
        assert get_resp.status_code == 200

        data = get_resp.json()
        assert data["evidence_id"] == body["evidence_id"]
        assert data["gate_id"] == body["gate_id"]
        assert data["signer_id"] == body["signer_id"]
        assert SHA256_RE.match(data["integrity"]["evidence_hash"])

    async def test_get_nonexistent_record_returns_404(self, api_client):
        """GET for a record that was never stored returns 404."""
        response = await api_client.get("/v1/evidence/DOES-NOT-EXIST-9999")

        assert response.status_code == 404
        assert "DOES-NOT-EXIST-9999" in response.json()["detail"]

    async def test_get_returns_same_hash_as_post(self, api_client, make_body):
        """
        GET must return the same evidence_hash that POST returned.

        Verifies the hash is persisted to DB and retrieved correctly.
        """
        body = make_body()

        with patch(MOCK_TARGET, new_callable=AsyncMock) as mock_gate:
            mock_gate.return_value = GATE_PASS_REPORT
            post_resp = await api_client.post("/v1/evidence", json=body)

        post_hash = post_resp.json()["integrity"]["evidence_hash"]

        get_resp = await api_client.get(f"/v1/evidence/{body['evidence_id']}")
        get_hash = get_resp.json()["integrity"]["evidence_hash"]

        assert post_hash == get_hash


# ─────────────────────────────────────────────────────────────────────────────
# Health check (sanity)
# ─────────────────────────────────────────────────────────────────────────────


class TestHealthReady:
    """Sanity check for the readiness probe."""

    async def test_health_ready_returns_200(self, api_client):
        """GET /health/ready returns 200 {"status": "ready"}."""
        response = await api_client.get("/health/ready")

        assert response.status_code == 200
        assert response.json()["status"] == "ready"
        assert response.json()["service"] == "evidence-ledger"
