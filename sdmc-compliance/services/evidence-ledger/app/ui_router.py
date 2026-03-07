"""
Web UI – SDMC Compliance Dashboard.

Provides HTML views for operator review and hackathon demonstration.
Built with FastAPI + Jinja2 templates.

Per NIST SP 800-53 AU-6 (Audit Review, Analysis, and Reporting)
"""
import os
import uuid
from datetime import date

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.repo.evidence_repo import EvidenceRepo
from app.schemas.evidence import EvidenceCreate, IntegrityIn
from app.services.opa_gate import evaluate_gate

# Resolve template directory relative to this file so it works in any
# working directory (including inside the Docker container at /app/).
_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=_TEMPLATE_DIR)

router = APIRouter(tags=["ui"])

# ── Gate metadata used across dashboard and submit views ──────────────────────

GATE_META: dict[str, dict] = {
    "gate-001-code-validation": {
        "number": "001",
        "name": "Code Validation",
        "sdmc": "SDMC §129.0302",
        "desc": "Verifies code section citation format and compliance criteria",
        "icon": "📋",
    },
    "gate-002-plan-review": {
        "number": "002",
        "name": "Plan Review",
        "sdmc": "CA B&P §6735",
        "desc": "Licensed engineer plan review and structural sign-off",
        "icon": "📐",
    },
    "gate-003-inspection": {
        "number": "003",
        "name": "Field Inspection",
        "sdmc": "SDMC §129.0310",
        "desc": "On-site inspection by certified building inspector",
        "icon": "🏗️",
    },
}


# ── Dashboard ──────────────────────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    """
    Render the compliance dashboard with gate status and evidence log.

    Fetches the 20 most recent records and runs the full chain integrity
    verification to display a live health status.

    Per NIST SP 800-53 AU-6 (Audit Review, Analysis, and Reporting)
    """
    repo = EvidenceRepo(db)

    # Most recent 20 records (desc order) for the evidence log table
    records = await repo.get_recent(20)

    # Full hash-chain integrity check for the status banner
    ok, checked, errors = await repo.verify_chain()

    # Build per-gate summary from the fetched records
    gate_status: dict[str, dict] = {
        gid: {**meta, "count": 0, "last_decision": None, "last_at": None}
        for gid, meta in GATE_META.items()
    }
    for r in records:
        gid = r.gate_id
        if gid in gate_status:
            gs = gate_status[gid]
            gs["count"] += 1
            if gs["last_at"] is None:
                # First match = most recent (records are newest-first)
                dec = r.decision_json
                if isinstance(dec, dict):
                    gs["last_decision"] = dec.get("decision", dec.get("result", "UNKNOWN"))
                gs["last_at"] = r.created_at

    success_id = request.query_params.get("success")
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "records": records,
            "integrity": {"ok": ok, "checked": checked, "errors": errors},
            "gate_status": gate_status,
            "success_id": success_id,
        },
    )


# ── Submit Permit (GET) ────────────────────────────────────────────────────────

@router.get("/submit", response_class=HTMLResponse)
async def submit_form(request: Request) -> HTMLResponse:
    """
    Render the permit submission form (Gate 001 – Code Section Validation).

    Pre-fills a permit ID based on today's date for quick demo use.
    Per SDMC §129.0302 (Building Permit Requirements)
    """
    today = date.today()
    permit_id = f"BP-{today.year}-{today.strftime('%m%d')}"
    return templates.TemplateResponse(
        "submit.html",
        {
            "request": request,
            "permit_id": permit_id,
            "result": None,
            "error": None,
        },
    )


# ── Submit Permit (POST) ───────────────────────────────────────────────────────

@router.post("/submit", response_class=HTMLResponse)
async def submit_permit(
    request: Request,
    db: AsyncSession = Depends(get_db),
    permit_id: str = Form(...),
    project_address: str = Form(...),
    applicant_name: str = Form(...),
    sdmc_version: str = Form(default="2024"),
    section_id: str = Form(default="SDMC-142.0503"),
    verification_method: str = Form(default="Inspection"),
    compliance_criteria: str = Form(default="Setback requirements verified per SDMC code"),
    signer_id: str = Form(...),
) -> HTMLResponse:
    """
    Process permit submission via Gate 001 – Code Section Validation.

    Flow:
      1. Build OPA gate inputs from form fields
      2. Evaluate gate-001 via OPA
      3a. PASS → store immutable evidence record → redirect to dashboard
      3b. FAIL → re-render form with OPA validation errors

    Per SDMC §129.0302 (Building Permit Requirements)
    Per NIST SP 800-53 AU-3 (Content of Audit Records)
    """
    today_str = date.today().strftime("%Y%m%d")
    suffix = uuid.uuid4().hex[:6].upper()
    evidence_id = f"{permit_id}-GATE001-{today_str}-{suffix}"

    # Build gate-001 input matching the OPA policy schema
    inputs = {
        "metadata": {
            "permit_id": permit_id,
            "project_address": project_address,
            "applicant_name": applicant_name,
            "sdmc_version": sdmc_version,
        },
        "code_sections": [
            {
                "Section_ID": section_id,
                "Verification_Method": verification_method,
                "Compliance_Criteria": [compliance_criteria],
            }
        ],
    }

    # ── OPA gate evaluation ────────────────────────────────────────────────────
    try:
        gate_report = await evaluate_gate("gate-001-code-validation", inputs)
    except Exception as exc:
        return templates.TemplateResponse(
            "submit.html",
            {
                "request": request,
                "permit_id": permit_id,
                "result": None,
                "error": f"Gate evaluation error: {exc}",
            },
        )

    decision = gate_report.get("decision", "FAIL")
    validation_errors = gate_report.get("validation_errors", [])

    if decision != "PASS":
        # Return form with OPA errors rendered inline
        return templates.TemplateResponse(
            "submit.html",
            {
                "request": request,
                "permit_id": permit_id,
                "result": {
                    "decision": "FAIL",
                    "validation_errors": validation_errors,
                    "evidence_id": evidence_id,
                },
                "error": None,
            },
        )

    # ── Store evidence record ──────────────────────────────────────────────────
    create_data = EvidenceCreate(
        evidence_id=evidence_id,
        gate_id="gate-001-code-validation",
        decision=gate_report,
        inputs=inputs,
        integrity=IntegrityIn(),  # client hashes ignored by repo
        signer_id=signer_id,
    )
    repo = EvidenceRepo(db)
    try:
        await repo.create(create_data)
    except Exception as exc:
        return templates.TemplateResponse(
            "submit.html",
            {
                "request": request,
                "permit_id": permit_id,
                "result": None,
                "error": f"Storage error: {exc}",
            },
        )

    # Redirect to dashboard with success banner
    return RedirectResponse(
        url=f"/dashboard?success={evidence_id}",
        status_code=303,
    )
