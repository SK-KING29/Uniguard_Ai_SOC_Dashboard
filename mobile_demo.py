"""
Mobile Remote Controller - server-side relay for the "This Device" mobile
demo simulation.

The mobile demo page (static/js/pages/mobiledemo.js, driven by
static/js/phoneattack.js) is a SAFE, CONTROLLED SIMULATION: pressing START
never sends real attack/flood traffic anywhere. It used to be pure
client-side JS state, which meant it only worked in the single browser tab
where it was pressed - a laptop on a different network never saw it.

This module is the small relay that fixes that: START/MITIGATE/STOP calls
from the phone update this in-memory store, and any dashboard (same
network or not) polls GET /api/mobile-demo/state and sees the same
incident. The traffic/risk NUMBERS are still simulated (smoothly computed
from elapsed wall-clock time, not random noise), exactly like the old
client-side version - only the transport is now real, via the backend.

source_ip is the one genuinely real value here: it's whatever address the
phone's own START request actually arrived from, read the same way the
real traffic middleware in app.py does.
"""
import math
import time
import threading

_INTENSITY_PROFILES = {
    "LOW": {"rate_target": 140, "conn_target": 35},
    "MEDIUM": {"rate_target": 420, "conn_target": 95},
    "HIGH": {"rate_target": 820, "conn_target": 180},
}
_RISK_TARGET = 87
_DEVICE_LABEL = "THIS DEVICE"
_THREAT_TYPE = "DOS-LIKE / HTTP FLOOD"
_TARGET_SERVICE = "Web Server (192.168.1.100)"
# Time constants chosen to feel like the original per-tick lerp(0.25/0.3)
# client animation, just expressed as a continuous function of real time.
_RAMP_TAU = 3.5
_DECAY_TAU = 2.2
_RESOLVE_AFTER = _DECAY_TAU * 4  # ~8.8s of decay before we call it RESOLVED


def _why_detected():
    return [
        "Request frequency increased sharply for this device",
        "Traffic exceeded the established baseline",
        "Repeated request behavior consistent with a flood pattern",
        "Connection behavior anomaly (many rapid connections from one device)",
    ]


def _severity_for(risk):
    return "CRITICAL" if risk >= 75 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 25 else "LOW"


class MobileDemoStore:
    """One active controlled simulation at a time (single-SOC demo, mirrors
    how the rest of this backend is a single-tenant demo instance)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._reset_locked()

    def _reset_locked(self):
        self.phase = "idle"  # idle | active | mitigating | resolved
        self.intensity = "MEDIUM"
        self.source_ip = None
        self.first_seen = None
        self.last_seen = None
        self.active_since = None
        self.mitigate_since = None
        self.mitigate_start_rate = 0.0
        self.mitigate_start_risk = 0.0
        self.mitigation_history = []

    def start(self, intensity, source_ip):
        if intensity not in _INTENSITY_PROFILES:
            intensity = "MEDIUM"
        with self._lock:
            self._reset_locked()
            now = time.time()
            self.phase = "active"
            self.intensity = intensity
            self.source_ip = source_ip
            self.first_seen = now
            self.last_seen = now
            self.active_since = now

    def stop(self):
        with self._lock:
            self._reset_locked()

    def mitigate(self):
        with self._lock:
            if self.phase != "active":
                return
            rate, risk, _conn = self._compute_locked()
            self.phase = "mitigating"
            self.mitigate_since = time.time()
            self.mitigate_start_rate = rate
            self.mitigate_start_risk = risk
            self.mitigation_history.append({
                "time": time.time(), "action": "RATE_LIMIT_BLOCK", "target": _DEVICE_LABEL,
            })

    def _compute_locked(self):
        """Returns (traffic_rate, risk_score, connection_rate) for right now,
        derived purely from elapsed wall-clock time - safe to call repeatedly
        (e.g. once per dashboard poll) with no drift or extra state."""
        now = time.time()
        profile = _INTENSITY_PROFILES.get(self.intensity, _INTENSITY_PROFILES["MEDIUM"])

        if self.phase == "active":
            elapsed = max(0.0, now - self.active_since)
            frac = 1 - math.exp(-elapsed / _RAMP_TAU)
            self.last_seen = now
            return profile["rate_target"] * frac, _RISK_TARGET * frac, profile["conn_target"] * frac

        if self.phase == "mitigating":
            elapsed = max(0.0, now - self.mitigate_since)
            decay = math.exp(-elapsed / _DECAY_TAU)
            self.last_seen = now
            rate = self.mitigate_start_rate * decay
            risk = self.mitigate_start_risk * decay
            if elapsed >= _RESOLVE_AFTER:
                self.phase = "resolved"
                return 0.0, 0.0, 0.0
            return rate, risk, 0.0

        return 0.0, 0.0, 0.0

    def snapshot(self):
        """JSON-serializable incident dict, or None if idle - same shape the
        old client-side UGPhone.getIncident() produced, so every page that
        already reads window.UGPhone.getIncident() keeps working unchanged."""
        with self._lock:
            if self.phase == "idle":
                return None

            rate, risk, conn = self._compute_locked()
            severity = "LOW" if self.phase == "resolved" else _severity_for(risk)
            status = {
                "active": "INVESTIGATING", "mitigating": "MITIGATING", "resolved": "RESOLVED",
            }.get(self.phase, "MONITORED")
            confidence = round(min(97.0, 58 + risk * 0.45), 1)
            evidence = _why_detected()
            if self.phase == "resolved":
                evidence = ["(historical) " + e for e in evidence]

            return {
                "id": "PHONE-DEVICE",
                "device": _DEVICE_LABEL,
                "source_ip": self.source_ip or "SIMULATED SOURCE",
                "target_service": _TARGET_SERVICE,
                "threat_type": _THREAT_TYPE,
                "severity": severity,
                "threat_score": round(risk),
                "confidence": confidence,
                "status": status,
                "first_detected": self.first_seen,
                "last_detected": self.last_seen,
                "traffic_rate": round(rate),
                "connection_rate": round(conn),
                "evidence": evidence,
                "mitigation_applied": self.mitigation_history[-1]["action"] if self.mitigation_history else None,
                "mitigation_history": list(self.mitigation_history),
                "source": "SIMULATED",
                "is_phone_device": True,
                "phase": self.phase,
                "intensity": self.intensity,
            }
