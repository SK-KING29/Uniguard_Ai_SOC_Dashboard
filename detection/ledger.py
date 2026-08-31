"""
Security Evidence Ledger - lightweight, hash-chained tamper-evident log.

SIH26145 theme note: this is the "Blockchain & Cybersecurity" half of the
project. AI/ML (detection/engine.py, detection/risk.py) does the actual
threat DETECTION. This module does NOT detect anything - it only protects
the INTEGRITY of alert evidence after the fact, so an investigator can
prove a stored alert record was not altered after it was written.

This is a local, permissioned-style cryptographic hash chain (SHA-256),
not a public/distributed blockchain and not a cryptocurrency system.
Every record cryptographically references the previous record's hash,
so any modification to a stored record - or reordering of records -
breaks the chain and is detectable by verify_chain().

Only security-event metadata is stored here. No packet payloads, no
request bodies, no raw traffic - only the same evidence fields already
shown on the SOC dashboard (threat class, confidence, risk score,
supporting evidence, detection reason, source-IP authenticity note).

In-memory by design, matching the rest of this prototype's state
(request_log, incidents, mitigation state all reset on restart / via
POST /api/reset) - this is a demo evidence ledger, not a production
forensic store.
"""
import hashlib
import json
import threading
import time

GENESIS_HASH = "0" * 64

# Fields that make up a record's evidence payload - used both when writing
# a record and when re-deriving its hash during verification, so the two
# can never silently drift apart.
_PAYLOAD_FIELDS = (
    "record_id", "timestamp", "alert_id", "flow_id", "threat_class",
    "confidence", "risk_score", "supporting_evidence", "detection_reason",
    "source_ip_authenticity",
)


def _hash_obj(obj) -> str:
    """Deterministic SHA-256 over a canonical (sorted-key) JSON encoding."""
    canonical = json.dumps(obj, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class EvidenceLedger:
    def __init__(self):
        self.lock = threading.Lock()
        self.records = []
        self._counter = 0

    def add_record(self, *, alert_id, flow_id, threat_class, confidence,
                    risk_score, supporting_evidence, detection_reason,
                    source_ip_authenticity):
        """Append a new evidence record, chained to the previous record's
        current_record_hash (or GENESIS_HASH for the first record)."""
        with self.lock:
            self._counter += 1
            record_id = f"EV-{self._counter:06d}"
            previous_record_hash = self.records[-1]["current_record_hash"] if self.records else GENESIS_HASH

            payload = {
                "record_id": record_id,
                "timestamp": time.time(),
                "alert_id": alert_id,
                "flow_id": flow_id,
                "threat_class": threat_class,
                "confidence": confidence,
                "risk_score": risk_score,
                "supporting_evidence": supporting_evidence,
                "detection_reason": detection_reason,
                "source_ip_authenticity": source_ip_authenticity,
            }
            evidence_hash = _hash_obj(payload)
            current_record_hash = _hash_obj({
                "evidence_hash": evidence_hash,
                "previous_record_hash": previous_record_hash,
            })

            record = {
                **payload,
                "evidence_hash": evidence_hash,
                "previous_record_hash": previous_record_hash,
                "current_record_hash": current_record_hash,
                "integrity_status": "VERIFIED",
            }
            self.records.append(record)
            return dict(record)

    def verify_chain(self):
        """Re-derive every hash from stored field values and confirm the
        chain is unbroken. Returns (ok: bool, broken_record_id, reason)."""
        with self.lock:
            expected_prev = GENESIS_HASH
            for r in self.records:
                payload = {k: r[k] for k in _PAYLOAD_FIELDS}
                expected_evidence_hash = _hash_obj(payload)
                if expected_evidence_hash != r["evidence_hash"]:
                    return False, r["record_id"], "evidence_hash mismatch - record content was altered"
                if r["previous_record_hash"] != expected_prev:
                    return False, r["record_id"], "previous_record_hash mismatch - chain link broken"
                expected_current = _hash_obj({
                    "evidence_hash": r["evidence_hash"],
                    "previous_record_hash": r["previous_record_hash"],
                })
                if expected_current != r["current_record_hash"]:
                    return False, r["record_id"], "current_record_hash mismatch - record tampered"
                expected_prev = r["current_record_hash"]
            return True, None, None

    def status(self):
        ok, broken_id, reason = self.verify_chain()
        return {
            "integrity_status": "VERIFIED" if ok else "TAMPER DETECTED",
            "record_count": len(self.records),
            "broken_record_id": broken_id,
            "reason": reason,
        }

    def snapshot(self, limit=50):
        with self.lock:
            recent = list(self.records[-limit:])
        st = self.status()
        return {"records": list(reversed(recent)), **st}

    def _tamper_for_test(self, index, field, value):
        """Test-only helper: simulates a record being altered after the
        fact, so verify_chain()'s tamper-detection path can be exercised.
        Never called from application code."""
        with self.lock:
            self.records[index][field] = value
