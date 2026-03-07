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
