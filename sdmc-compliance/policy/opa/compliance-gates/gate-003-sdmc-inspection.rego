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
	"Third-Party Report Review",
}

VALID_RESULTS := {
	"PASS",
	"FAIL",
	"CONDITIONAL_PASS",
	"PENDING_CORRECTION",
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
		"inspections_passed":             count([a | some a in input.inspection_activities; a.Result == "PASS"]),
		"inspections_failed":             count([a | some a in input.inspection_activities; a.Result == "FAIL"]),
		"validation_errors":              count(validation_errors),
	},
	"validation_errors": validation_errors,
	"timestamp":         time.now_ns() / 1000000,
}

final_decision := "PASS" if {
	count(validation_errors) == 0
}

final_decision := "FAIL" if {
	count(validation_errors) > 0
}

# ─────────────────────────────────────────────────────────────────────────────
# Coverage Calculations
# ─────────────────────────────────────────────────────────────────────────────

inspected_sections := {sid |
	some sid in input.code_section_ids
	some act in input.inspection_activities
	sid in act.Code_Sections
}

uninspected_sections := {sid |
	some sid in input.code_section_ids
	not sid in inspected_sections
}

verified_plans := {pid |
	some pid in input.plan_document_ids
	some act in input.inspection_activities
	pid in act.Plans_Verified
}

unverified_plans := {pid |
	some pid in input.plan_document_ids
	not pid in verified_plans
}

code_coverage_percent := 100 if {
	count(input.code_section_ids) == 0
}

code_coverage_percent := v if {
	count(input.code_section_ids) > 0
	v := round((count(inspected_sections) / count(input.code_section_ids)) * 100)
}

plans_coverage_percent := 100 if {
	count(input.plan_document_ids) == 0
}

plans_coverage_percent := v if {
	count(input.plan_document_ids) > 0
	v := round((count(verified_plans) / count(input.plan_document_ids)) * 100)
}

# ─────────────────────────────────────────────────────────────────────────────
# Validation Rules
# ─────────────────────────────────────────────────────────────────────────────

validation_errors[msg] if {
	not has_valid_metadata
	msg := "METADATA ERROR: Missing required fields (permit_id, inspection_date, inspector_id, inspector_license). Per NIST SP 800-53 AU-3 (Content of audit records)."
}

validation_errors[msg] if {
	some sid in uninspected_sections
	msg := sprintf(
		"COVERAGE ERROR: Code section '%v' was not inspected. Per SDMC §129.0306 (Inspection requirements).",
		[sid],
	)
}

validation_errors[msg] if {
	some pid in unverified_plans
	msg := sprintf(
		"PLAN ERROR: Plan document '%v' was not verified during inspection. Per SDMC §129.0306 (Inspection requirements).",
		[pid],
	)
}

validation_errors[msg] if {
	some act in input.inspection_activities
	not act.Method in VALID_METHODS
	msg := sprintf(
		"METHOD ERROR: Inspection '%v' has invalid method '%v'. Valid methods: Visual Inspection, Testing, Measurement, Third-Party Report Review. Per SDMC §129.0306 (Inspection requirements).",
		[act.Inspection_ID, act.Method],
	)
}

validation_errors[msg] if {
	some act in input.inspection_activities
	not act.Result in VALID_RESULTS
	msg := sprintf(
		"RESULT ERROR: Inspection '%v' has invalid result '%v'. Valid results: PASS, FAIL, CONDITIONAL_PASS, PENDING_CORRECTION. Per SDMC §129.0306 (Inspection requirements).",
		[act.Inspection_ID, act.Result],
	)
}

validation_errors[msg] if {
	some act in input.inspection_activities
	act.Result == "FAIL"
	msg := sprintf(
		"FAILED INSPECTION: Inspection '%v' FAILED for code sections %v. Per SDMC §129.0308 (Stop work orders) - failed inspections require correction before permit approval.",
		[act.Inspection_ID, act.Code_Sections],
	)
}

validation_errors[msg] if {
	some act in input.inspection_activities
	act.Findings == ""
	msg := sprintf(
		"DOCUMENTATION ERROR: Inspection '%v' has no Findings. Per NIST SP 800-53 AU-6 (Audit review, analysis, and reporting).",
		[act.Inspection_ID],
	)
}

validation_errors[msg] if {
	some act in input.inspection_activities
	act.Photos_Attached != true
	msg := sprintf(
		"DOCUMENTATION ERROR: Inspection '%v' has no photos attached. Per NIST SP 800-53 AU-6 (Audit review, analysis, and reporting).",
		[act.Inspection_ID],
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
