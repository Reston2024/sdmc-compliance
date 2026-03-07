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

        Uses SELECT FOR UPDATE to serialize concurrent inserts.
        Returns GENESIS_HASH if no records exist.

        Per 21 CFR Part 11 §11.10(e): sequential record ordering.
        Per NIST SP 800-53 AU-8: time-ordered audit records.
        Per NIST SP 800-53 AU-9: prevent concurrent hash chain corruption.
        """
        result = await self.db.execute(
            select(EvidenceRecord.evidence_hash)
            .order_by(EvidenceRecord.created_at.desc())
            .limit(1)
            .with_for_update()
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
        # Concurrency note: _get_last_hash() uses SELECT FOR UPDATE to serialize
        # concurrent inserts. Two concurrent create() calls will be serialized
        # at the database level, ensuring each gets a unique previous_hash.
        # Per NIST SP 800-53 AU-9 (Protection of Audit Information).
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

    async def get_recent(self, limit: int = 20) -> list[EvidenceRecord]:
        """
        Retrieve the most recent evidence records for dashboard display.

        Returns records in descending creation order (newest first).
        Per NIST SP 800-53 AU-6 (Audit Review, Analysis, and Reporting)
        """
        result = await self.db.execute(
            select(EvidenceRecord)
            .order_by(EvidenceRecord.created_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_all_ordered(self) -> list[EvidenceRecord]:
        """
        Retrieve all records in creation order for integrity verification.

        Per NIST SP 800-53 AU-11 (Audit Record Retention)
        """
        result = await self.db.execute(
            select(EvidenceRecord).order_by(EvidenceRecord.created_at.asc())
        )
        return list(result.scalars().all())

    async def verify_chain(self) -> tuple[bool, int, list[str]]:
        """
        Verify the hash chain integrity of ALL evidence records.

        For each record, recomputes the expected hash from stored fields
        and compares to the stored evidence_hash. Also verifies the
        previous_hash linkage is correct.

        Returns (ok, count_of_records_checked, list_of_failing_evidence_ids).

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

        return len(errors) == 0, len(records), errors
