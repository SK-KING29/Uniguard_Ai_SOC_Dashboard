"""
Incident lifecycle state machine. Deliberately pure Python with zero
FastAPI/Starlette dependency, so it can be unit-tested directly (see
tests/test_incident_manager.py) without needing a running ASGI server.

Turns a stream of (window, analysis, risk) - each produced from REAL
logged traffic in app.py - into: system status, open/close incidents,
a timeline, and recovery tracking.

Includes a short debounce (ALERT_DEBOUNCE_WINDOWS) so a single noisy
1-second reading cannot flip system status or open a false incident.
A real attack ramps up and stays elevated for multiple seconds, so this
costs ~1-2 seconds of extra detection latency while eliminating
single-frame false alarms - a deliberate, standard IDS trade-off.

Optional `ledger` (detection/ledger.py EvidenceLedger) and
`source_authenticity_fn` (detection/source_authenticity.py) params are
purely additive: when omitted (as every existing test in
tests/test_detection_logic.py does), this class behaves exactly as
before. When supplied, every incident open/escalate/mitigate/resolve
event is written to the hash-chained evidence ledger and every incident
carries the standardized SIH26145 alert-schema fields
(threat_class, confidence, flow_id, source_ip_authenticity,
evidence_hash, previous_record_hash, current_record_hash,
integrity_status).
"""
import time
import uuid
from collections import deque

ALERT_DEBOUNCE_WINDOWS = 2
RECOVERY_CALM_WINDOWS_NEEDED = 5


def _default_source_authenticity(window):
    from .source_authenticity import assess_source_authenticity
    return assess_source_authenticity(window)


class IncidentManager:
    def __init__(self, ledger=None, source_authenticity_fn=None):
        self.system_status = "PROTECTED"       # PROTECTED | SUSPICIOUS | ATTACK
        self.current_window = None
        self.history = deque(maxlen=300)
        self.timeline = deque(maxlen=100)
        self.incidents = {}
        self.active_incident_id = None
        self.recovery = {"in_progress": False, "consecutive_calm_windows": 0, "peak_rate": 0.0}
        self._alert_streak = 0
        self.ledger = ledger
        self._source_authenticity_fn = source_authenticity_fn or _default_source_authenticity

    def _add_timeline(self, label, kind="info"):
        self.timeline.append({"time": time.time(), "label": label, "kind": kind})

    def log_event(self, label, kind="info"):
        """Public entry point for callers outside this class (e.g. app.py
        logging a startup event) - avoids reaching into the private
        _add_timeline method directly."""
        self._add_timeline(label, kind)

    def process_window(self, window, analysis, risk):
        self.current_window = {**window, **analysis, **risk}
        self.history.append(self.current_window)
        self.recovery["peak_rate"] = max(self.recovery["peak_rate"], window["req_per_sec"])

        status = risk["status"]

        if status in ("SUSPICIOUS", "ATTACK"):
            self.recovery["consecutive_calm_windows"] = 0
            self._alert_streak += 1

            if self.active_incident_id is None:
                if self._alert_streak < ALERT_DEBOUNCE_WINDOWS:
                    # Not sustained yet - a single noisy window should not
                    # trigger a false alarm. Stay PROTECTED until confirmed.
                    self.system_status = "PROTECTED"
                    return self.current_window
                self._open_incident(window, analysis, risk)
            else:
                self._update_incident(window, analysis, risk)

            self.system_status = "ATTACK" if status == "ATTACK" else "SUSPICIOUS"
        else:
            self._alert_streak = 0
            self._advance_recovery(window)

        return self.current_window

    def _standardized_fields(self, window, risk):
        """Additive SIH26145 standardized-alert-schema fields (section 4 of
        the spec): threat_class, confidence, flow_id, source_ip_authenticity,
        detection_reason - independent of whether a ledger is attached."""
        source_auth = self._source_authenticity_fn(window)
        threat_class = "HTTP FLOOD / DOS-LIKE" if risk["status"] == "ATTACK" else \
            ("ANOMALOUS TRAFFIC PATTERN" if risk["status"] == "SUSPICIOUS" else "NORMAL")
        return {
            "threat_class": threat_class,
            "confidence": round(risk["risk_score"] / 100.0, 3),
            "source_ip_authenticity": source_auth,
            "detection_reason": "; ".join(risk["evidence"]),
            "protocol": "HTTP (application layer)",
            "source_port": None,
            "destination_port": None,
            "packets": None,
            "packet_rate": None,
            "byte_rate": round(window.get("bytes_per_sec", 0.0), 1),
            "destination_ip": "N/A (application-layer monitoring - no packet capture)",
        }

    def _record_evidence(self, inc, reason_kind):
        """Write one evidence record to the hash-chained ledger for this
        incident's current state, and mirror the resulting hash-chain
        fields + integrity status back onto the incident dict itself so
        the dashboard can show them without a second lookup."""
        if not self.ledger:
            return
        record = self.ledger.add_record(
            alert_id=f"{inc['id']}-{reason_kind}",
            flow_id=inc["id"],
            threat_class=inc.get("threat_class", "UNKNOWN"),
            confidence=inc.get("confidence", 0.0),
            risk_score=inc["threat_score"],
            supporting_evidence=inc["evidence"],
            detection_reason=inc.get("detection_reason", ""),
            source_ip_authenticity=inc.get("source_ip_authenticity", {}),
        )
        inc["evidence_hash"] = record["evidence_hash"]
        inc["previous_record_hash"] = record["previous_record_hash"]
        inc["current_record_hash"] = record["current_record_hash"]
        inc["integrity_status"] = self.ledger.status()["integrity_status"]
        inc["evidence_record_id"] = record["record_id"]

    def _open_incident(self, window, analysis, risk):
        inc_id = f"UG-{uuid.uuid4().hex[:6].upper()}"
        self.active_incident_id = inc_id
        inc = {
            "id": inc_id,
            "flow_id": inc_id,
            "first_detected": window["t"],
            "last_detected": window["t"],
            "status": "ACTIVE",
            "affected_endpoint": max(window["per_endpoint"], key=window["per_endpoint"].get) if window["per_endpoint"] else None,
            "source_ip": window["top_ip"],
            "peak_rate": window["req_per_sec"],
            "baseline_rate": analysis["baseline_rate"],
            "threat_score": risk["risk_score"],
            "severity": risk["severity"],
            "evidence": risk["evidence"],
            "mitigation_applied": None,
            "mitigation_applied_at": None,
        }
        inc.update(self._standardized_fields(window, risk))
        self.incidents[inc_id] = inc
        self._record_evidence(inc, "OPEN")
        self._add_timeline(
            "Possible DoS detected - incident opened" if risk["status"] == "ATTACK"
            else "Anomaly detected - incident opened",
            "critical" if risk["status"] == "ATTACK" else "warning",
        )
        self.recovery = {"in_progress": False, "consecutive_calm_windows": 0, "peak_rate": window["req_per_sec"]}

    def _update_incident(self, window, analysis, risk):
        inc = self.incidents[self.active_incident_id]
        prev_severity = inc["severity"]
        inc["last_detected"] = window["t"]
        inc["peak_rate"] = max(inc["peak_rate"], window["req_per_sec"])
        inc["threat_score"] = risk["risk_score"]
        inc["severity"] = risk["severity"]
        inc["evidence"] = risk["evidence"]
        inc.update(self._standardized_fields(window, risk))
        if inc["status"] == "ACTIVE" and risk["status"] == "ATTACK" and prev_severity != "CRITICAL":
            self._add_timeline("Threshold exceeded - possible DoS attack detected", "critical")
            self._record_evidence(inc, "ESCALATE")

    def _advance_recovery(self, window):
        if self.active_incident_id is None:
            self.system_status = "PROTECTED"
            return
        self.recovery["consecutive_calm_windows"] += 1
        if self.recovery["consecutive_calm_windows"] >= RECOVERY_CALM_WINDOWS_NEEDED:
            inc = self.incidents[self.active_incident_id]
            inc["status"] = "RESOLVED"
            inc["resolved_at"] = window["t"]
            self._record_evidence(inc, "RESOLVE")
            self.active_incident_id = None
            self.system_status = "PROTECTED"
            self._add_timeline("Traffic normalized - system recovered", "success")
        else:
            self.system_status = "SUSPICIOUS"

    def apply_mitigation(self, action, label):
        """Applies to the EXISTING application-layer mitigation path only
        (mitigation/controls.py) - this is intentionally NOT part of the
        SIH26145 passive/read-only monitoring pipeline. See
        'mitigation_path' in the returned incident dict and
        /api/sih-alignment for the explicit separation."""
        if self.active_incident_id:
            inc = self.incidents[self.active_incident_id]
            inc["status"] = "MITIGATING"
            inc["mitigation_applied"] = action
            inc["mitigation_applied_at"] = time.time()
            inc["mitigation_path"] = "ACTIVE_APPLICATION_LAYER"  # NOT the SIH passive path
            self._record_evidence(inc, "MITIGATE")
            self.recovery = {"in_progress": True, "consecutive_calm_windows": 0,
                              "peak_rate": self.recovery["peak_rate"]}
        self._add_timeline(label, "action")

    def reset(self):
        self.system_status = "PROTECTED"
        self.current_window = None
        self.history.clear()
        self.timeline.clear()
        self.incidents.clear()
        self.active_incident_id = None
        self.recovery = {"in_progress": False, "consecutive_calm_windows": 0, "peak_rate": 0.0}
        self._alert_streak = 0
        self._add_timeline("Demo reset - baseline monitoring restarted", "info")

    def snapshot(self):
        active = self.incidents.get(self.active_incident_id) if self.active_incident_id else None
        return {
            "system_status": self.system_status,
            "current": self.current_window or {},
            "history": list(self.history)[-120:],
            "active_incident": active,
            "incidents": sorted(self.incidents.values(), key=lambda i: i["first_detected"], reverse=True)[:20],
            "timeline": list(self.timeline)[-30:],
        }
