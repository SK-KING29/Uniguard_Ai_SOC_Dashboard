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
"""
import time
import uuid
from collections import deque

ALERT_DEBOUNCE_WINDOWS = 2
RECOVERY_CALM_WINDOWS_NEEDED = 5


class IncidentManager:
    def __init__(self):
        self.system_status = "PROTECTED"       # PROTECTED | SUSPICIOUS | ATTACK
        self.current_window = None
        self.history = deque(maxlen=300)
        self.timeline = deque(maxlen=100)
        self.incidents = {}
        self.active_incident_id = None
        self.recovery = {"in_progress": False, "consecutive_calm_windows": 0, "peak_rate": 0.0}
        self._alert_streak = 0

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

    def _open_incident(self, window, analysis, risk):
        inc_id = f"UG-{uuid.uuid4().hex[:6].upper()}"
        self.active_incident_id = inc_id
        self.incidents[inc_id] = {
            "id": inc_id,
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
        if inc["status"] == "ACTIVE" and risk["status"] == "ATTACK" and prev_severity != "CRITICAL":
            self._add_timeline("Threshold exceeded - possible DoS attack detected", "critical")

    def _advance_recovery(self, window):
        if self.active_incident_id is None:
            self.system_status = "PROTECTED"
            return
        self.recovery["consecutive_calm_windows"] += 1
        if self.recovery["consecutive_calm_windows"] >= RECOVERY_CALM_WINDOWS_NEEDED:
            inc = self.incidents[self.active_incident_id]
            inc["status"] = "RESOLVED"
            inc["resolved_at"] = window["t"]
            self.active_incident_id = None
            self.system_status = "PROTECTED"
            self._add_timeline("Traffic normalized - system recovered", "success")
        else:
            self.system_status = "SUSPICIOUS"

    def apply_mitigation(self, action, label):
        if self.active_incident_id:
            inc = self.incidents[self.active_incident_id]
            inc["status"] = "MITIGATING"
            inc["mitigation_applied"] = action
            inc["mitigation_applied_at"] = time.time()
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
