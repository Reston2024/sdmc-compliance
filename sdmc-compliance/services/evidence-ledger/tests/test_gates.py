"""
Unit tests for the OPA gate evaluation service.

Tests evaluate_gate() and gate_allows() by intercepting outbound httpx calls
with pytest-httpx's httpx_mock fixture.  No FastAPI, no DB — pure unit tests.

Per NIST SP 800-53 SA-11 (Developer Testing and Evaluation)
Per NIST SP 800-53 CA-2 (Control Assessments)
"""
import pytest
import httpx
from pytest_httpx import HTTPXMock

from app.services.opa_gate import (
    GATE_POLICY_MAP,
    OPA_URL,
    evaluate_gate,
    gate_allows,
)

# ── Constants ──────────────────────────────────────────────────────────────
GATE_001 = "gate-001-code-validation"
GATE_002 = "gate-002-plan-review"
GATE_003 = "gate-003-inspection"

# Minimal input dict — gate logic is in OPA, not in the service layer
DUMMY_INPUT: dict = {"metadata": {"permit_id": "BP-2026-00001"}}

# OPA URL helpers
_URL_001 = f"{OPA_URL}/v1/data/compliance/gates/sdmc_code_validation/gate_report"
_URL_002 = f"{OPA_URL}/v1/data/compliance/gates/sdmc_plan_review/gate_report"
_URL_003 = f"{OPA_URL}/v1/data/compliance/gates/sdmc_inspection/gate_report"

PASS_REPORT = {
    "decision": "PASS",
    "gate_id": "001",
    "gate_name": "Code Section Validation",
    "validation_errors": [],
    "timestamp": 1741305600000,
}

FAIL_REPORT = {
    "decision": "FAIL",
    "gate_id": "001",
    "gate_name": "Code Section Validation",
    "validation_errors": [
        "FORMAT ERROR: Section_ID 'X' does not match pattern. Per SDMC §129.0302."
    ],
    "timestamp": 1741305600000,
}


# ─────────────────────────────────────────────────────────────────────────────
# evaluate_gate()
# ─────────────────────────────────────────────────────────────────────────────


class TestEvaluateGate:
    """Tests for the evaluate_gate() service function."""

    async def test_pass_response_returned_as_dict(self, httpx_mock: HTTPXMock):
        """OPA PASS response → evaluate_gate returns the unwrapped result dict."""
        httpx_mock.add_response(
            url=_URL_001,
            method="POST",
            json={"result": PASS_REPORT},
        )

        report = await evaluate_gate(GATE_001, DUMMY_INPUT)

        assert report["decision"] == "PASS"
        assert report["validation_errors"] == []

    async def test_fail_response_includes_errors(self, httpx_mock: HTTPXMock):
        """OPA FAIL response → evaluate_gate returns result with error list."""
        httpx_mock.add_response(
            url=_URL_001,
            method="POST",
            json={"result": FAIL_REPORT},
        )

        report = await evaluate_gate(GATE_001, DUMMY_INPUT)

        assert report["decision"] == "FAIL"
        assert len(report["validation_errors"]) == 1
        assert "FORMAT ERROR" in report["validation_errors"][0]

    async def test_unknown_gate_raises_value_error_immediately(self):
        """Unknown gate_id raises ValueError before any HTTP call — no network needed."""
        with pytest.raises(ValueError, match="Unknown gate_id"):
            await evaluate_gate("gate-999-nonexistent", DUMMY_INPUT)

    async def test_opa_500_raises_http_status_error(self, httpx_mock: HTTPXMock):
        """OPA 5xx response → httpx.HTTPStatusError propagates to caller."""
        httpx_mock.add_response(
            url=_URL_001,
            method="POST",
            status_code=500,
        )

        with pytest.raises(httpx.HTTPStatusError):
            await evaluate_gate(GATE_001, DUMMY_INPUT)

    async def test_missing_result_key_returns_empty_dict(self, httpx_mock: HTTPXMock):
        """
        OPA response missing the 'result' key → returns {} (deny-by-default).

        This is the safe fallback when OPA returns an empty body for a
        policy that has no matching rule.
        """
        httpx_mock.add_response(
            url=_URL_001,
            method="POST",
            json={},  # no 'result' wrapper
        )

        report = await evaluate_gate(GATE_001, DUMMY_INPUT)

        assert report == {}

    async def test_gate_001_url_is_correct(self, httpx_mock: HTTPXMock):
        """POST goes to the sdmc_code_validation package path."""
        httpx_mock.add_response(url=_URL_001, method="POST", json={"result": PASS_REPORT})

        await evaluate_gate(GATE_001, DUMMY_INPUT)

        # If url didn't match, pytest-httpx would raise a NoMatchFound error
        assert len(httpx_mock.get_requests()) == 1
        assert "sdmc_code_validation" in str(httpx_mock.get_requests()[0].url)

    async def test_gate_002_url_is_correct(self, httpx_mock: HTTPXMock):
        """POST goes to the sdmc_plan_review package path."""
        httpx_mock.add_response(url=_URL_002, method="POST", json={"result": PASS_REPORT})

        await evaluate_gate(GATE_002, DUMMY_INPUT)

        assert "sdmc_plan_review" in str(httpx_mock.get_requests()[0].url)

    async def test_gate_003_url_is_correct(self, httpx_mock: HTTPXMock):
        """POST goes to the sdmc_inspection package path."""
        httpx_mock.add_response(url=_URL_003, method="POST", json={"result": PASS_REPORT})

        await evaluate_gate(GATE_003, DUMMY_INPUT)

        assert "sdmc_inspection" in str(httpx_mock.get_requests()[0].url)

    async def test_request_body_wraps_input_correctly(self, httpx_mock: HTTPXMock):
        """evaluate_gate POSTs {"input": input_data} to OPA REST API."""
        httpx_mock.add_response(url=_URL_001, method="POST", json={"result": PASS_REPORT})

        await evaluate_gate(GATE_001, DUMMY_INPUT)

        req = httpx_mock.get_requests()[0]
        import json
        body = json.loads(req.content)
        assert "input" in body
        assert body["input"] == DUMMY_INPUT


# ─────────────────────────────────────────────────────────────────────────────
# gate_allows()
# ─────────────────────────────────────────────────────────────────────────────


class TestGateAllows:
    """Tests for the gate_allows() convenience wrapper."""

    async def test_pass_decision_returns_true_empty_errors(self, httpx_mock: HTTPXMock):
        """PASS decision → (True, [])."""
        httpx_mock.add_response(
            url=_URL_001,
            method="POST",
            json={"result": {"decision": "PASS", "validation_errors": []}},
        )

        allowed, errors = await gate_allows(GATE_001, DUMMY_INPUT)

        assert allowed is True
        assert errors == []

    async def test_fail_decision_returns_false_with_errors(self, httpx_mock: HTTPXMock):
        """FAIL decision → (False, [error list])."""
        httpx_mock.add_response(
            url=_URL_001,
            method="POST",
            json={
                "result": {
                    "decision": "FAIL",
                    "validation_errors": ["FORMAT ERROR: bad section id"],
                }
            },
        )

        allowed, errors = await gate_allows(GATE_001, DUMMY_INPUT)

        assert allowed is False
        assert len(errors) == 1
        assert "FORMAT ERROR" in errors[0]

    async def test_missing_decision_field_defaults_to_fail(self, httpx_mock: HTTPXMock):
        """
        OPA result without 'decision' key → defaults to FAIL (deny by default).

        Security invariant: missing = deny, not allow.
        """
        httpx_mock.add_response(
            url=_URL_001,
            method="POST",
            json={"result": {"validation_errors": []}},  # no 'decision' key
        )

        allowed, errors = await gate_allows(GATE_001, DUMMY_INPUT)

        assert allowed is False

    async def test_missing_validation_errors_defaults_to_empty(self, httpx_mock: HTTPXMock):
        """OPA result without 'validation_errors' → errors defaults to []."""
        httpx_mock.add_response(
            url=_URL_001,
            method="POST",
            json={"result": {"decision": "PASS"}},  # no 'validation_errors'
        )

        allowed, errors = await gate_allows(GATE_001, DUMMY_INPUT)

        assert allowed is True
        assert errors == []


# ─────────────────────────────────────────────────────────────────────────────
# GATE_POLICY_MAP registration
# ─────────────────────────────────────────────────────────────────────────────


class TestGatePolicyMap:
    """Static checks on the GATE_POLICY_MAP configuration."""

    def test_all_three_gates_registered(self):
        """All three SDMC gates must be present in GATE_POLICY_MAP."""
        assert GATE_001 in GATE_POLICY_MAP
        assert GATE_002 in GATE_POLICY_MAP
        assert GATE_003 in GATE_POLICY_MAP

    def test_policy_paths_use_forward_slashes(self):
        """OPA package paths use '/' not '.' as separators in REST API URLs."""
        for gate_id, path in GATE_POLICY_MAP.items():
            assert "/" in path, f"{gate_id}: path must use '/' separators, got '{path}'"
            assert "." not in path, f"{gate_id}: path must not use '.' separators"

    def test_gate_001_path_contains_sdmc_code_validation(self):
        assert "sdmc_code_validation" in GATE_POLICY_MAP[GATE_001]

    def test_gate_002_path_contains_sdmc_plan_review(self):
        assert "sdmc_plan_review" in GATE_POLICY_MAP[GATE_002]

    def test_gate_003_path_contains_sdmc_inspection(self):
        assert "sdmc_inspection" in GATE_POLICY_MAP[GATE_003]
