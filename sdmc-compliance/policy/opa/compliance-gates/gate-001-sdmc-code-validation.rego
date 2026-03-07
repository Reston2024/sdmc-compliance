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

# Valid verification methods per SDMC inspection procedures
VALID_VERIFICATION_METHODS := {
	"Inspection",
	"Plan Review",
	"Calculation Review",
	"Testing",
	"Third-Party Certification",
}

# SDMC section ID format: SDMC-###.####
SECTION_ID_PATTERN := `^SDMC-[0-9]{3}\.[0-9]{4}$`

# ─────────────────────────────────────────────────────────────────────────────
# Main gate report - single output used by Evidence Ledger service
# ─────────────────────────────────────────────────────────────────────────────

gate_report := {
	"decision":           final_decision,
	"gate_id":            "001",
	"gate_name":          "Code Section Validation",
	"sections_evaluated": count(input.code_sections),
	"sections_passed":    count([s | s := input.code_sections[_]; section_valid(s)]),
	"statistics": {
		"total_sections":         count(input.code_sections),
		"sections_with_criteria": count([s | s := input.code_sections[_]; count(s.Compliance_Criteria) > 0]),
		"valid_format":           count([s | s := input.code_sections[_]; regex.match(SECTION_ID_PATTERN, s.Section_ID)]),
		"validation_errors":      count(validation_errors),
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
# Validation Rules
# ─────────────────────────────────────────────────────────────────────────────

validation_errors[msg] if {
	not has_valid_metadata
	msg := "METADATA ERROR: Missing required fields (permit_id, project_address, applicant_name, sdmc_version). Per NIST SP 800-53 AU-3 (Content of audit records)."
}

validation_errors[msg] if {
	not has_unique_section_ids
	msg := "DUPLICATE ERROR: Duplicate Section_IDs detected. Per SDMC §129.0302 (Building permit requirements) - each code section must appear once."
}

validation_errors[msg] if {
	some s in input.code_sections
	not regex.match(SECTION_ID_PATTERN, s.Section_ID)
	msg := sprintf(
		"FORMAT ERROR: Section_ID '%v' does not match pattern SDMC-###.#### (e.g., SDMC-142.0503). Per SDMC §129.0302 (Building permit requirements).",
		[s.Section_ID],
	)
}

validation_errors[msg] if {
	some s in input.code_sections
	not s.Verification_Method in VALID_VERIFICATION_METHODS
	msg := sprintf(
		"METHOD ERROR: Section '%v' has invalid Verification_Method '%v'. Valid methods: Inspection, Plan Review, Calculation Review, Testing, Third-Party Certification. Per SDMC §129.0306 (Inspection requirements).",
		[s.Section_ID, s.Verification_Method],
	)
}

validation_errors[msg] if {
	some s in input.code_sections
	count(s.Compliance_Criteria) == 0
	msg := sprintf(
		"CRITERIA ERROR: Section '%v' has no Compliance_Criteria. Each section must list specific verification criteria. Per NIST SP 800-53 CA-2 (Control assessments).",
		[s.Section_ID],
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
	ids := [s.Section_ID | some s in input.code_sections]
	count(ids) == count({id | some id in ids})
}

section_valid(s) if {
	regex.match(SECTION_ID_PATTERN, s.Section_ID)
	s.Verification_Method in VALID_VERIFICATION_METHODS
	count(s.Compliance_Criteria) > 0
}
