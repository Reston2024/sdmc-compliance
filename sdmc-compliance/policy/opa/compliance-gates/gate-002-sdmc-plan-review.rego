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
	"Site Plan",
}

# Pattern: exactly 5 digits, full-string match, e.g. #12345
LICENSE_PATTERN := `^#[0-9]{5}$`

# ─────────────────────────────────────────────────────────────────────────────
# Main gate report
# ─────────────────────────────────────────────────────────────────────────────

gate_report := {
	"decision":                 final_decision,
	"gate_id":                  "002",
	"gate_name":                "Plan Review Compliance",
	"code_sections_evaluated":  count(input.code_section_ids),
	"plan_documents_evaluated": count(input.plan_documents),
	"statistics": {
		"coverage_percent":     coverage_percent,
		"sections_covered":     count(covered_sections),
		"sections_not_covered": count(uncovered_sections),
		"plans_traced":         count(traced_plans),
		"plans_orphaned":       count(orphaned_plans),
		"validation_errors":    count(validation_errors),
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

# Set of code section IDs covered by at least one plan document
covered_sections := {sid |
	some sid in input.code_section_ids
	some doc in input.plan_documents
	sid in doc.Code_Sections
}

uncovered_sections := {sid |
	some sid in input.code_section_ids
	not sid in covered_sections
}

# Plans that trace to at least one required code section
traced_plans := {doc.Document_ID |
	some doc in input.plan_documents
	some sid in doc.Code_Sections
	sid in input.code_section_ids
}

orphaned_plans := {doc.Document_ID |
	some doc in input.plan_documents
	not doc.Document_ID in traced_plans
}

coverage_percent := 100 if {
	count(input.code_section_ids) == 0
}

coverage_percent := v if {
	count(input.code_section_ids) > 0
	v := round((count(covered_sections) / count(input.code_section_ids)) * 100)
}

# ─────────────────────────────────────────────────────────────────────────────
# Validation Rules
# ─────────────────────────────────────────────────────────────────────────────

validation_errors[msg] if {
	not has_valid_metadata
	msg := "METADATA ERROR: Missing required fields (permit_id, review_date, reviewer_id, plan_review_status). Per NIST SP 800-53 AU-3 (Content of audit records)."
}

validation_errors[msg] if {
	input.metadata.plan_review_status != "APPROVED"
	msg := sprintf(
		"STATUS ERROR: plan_review_status is '%v', must be 'APPROVED'. Per SDMC §129.0304 (Plan review procedures).",
		[input.metadata.plan_review_status],
	)
}

validation_errors[msg] if {
	some sid in uncovered_sections
	msg := sprintf(
		"COVERAGE ERROR: Code section '%v' is not covered by any plan document. Per NIST SP 800-53 CM-3 (Configuration change control).",
		[sid],
	)
}

validation_errors[msg] if {
	some doc_id in orphaned_plans
	msg := sprintf(
		"TRACEABILITY ERROR: Plan document '%v' does not trace to any required code section. Per NIST SP 800-53 CM-3 (Configuration change control).",
		[doc_id],
	)
}

validation_errors[msg] if {
	some doc in input.plan_documents
	not doc.Document_Type in VALID_DOCUMENT_TYPES
	msg := sprintf(
		"TYPE ERROR: Plan '%v' has invalid Document_Type '%v'. Per SDMC §129.0304 (Plan review procedures).",
		[doc.Document_ID, doc.Document_Type],
	)
}

validation_errors[msg] if {
	some doc in input.plan_documents
	not regex.match(LICENSE_PATTERN, doc.Prepared_By)
	msg := sprintf(
		"STAMP ERROR: Plan '%v' Prepared_By field '%v' does not contain a license number (format: #NNNNN). Per California Business and Professions Code §6735 (Engineer seal requirements).",
		[doc.Document_ID, doc.Prepared_By],
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
