"""
IP intelligence heuristics - computed from REAL logged HTTP requests
(request_log in app.py). Application-layer only: user-agent consistency
and request-timing regularity. No packet-level fingerprinting, no
geolocation (no GeoIP database is bundled - would require an external
paid/keyed service, so it is intentionally not faked here).

This does NOT claim to identify a real attacker. It only describes
observed behavioral patterns of the traffic attributed to one source IP.
"""
import statistics


def compute_ip_intel(ip: str, events: list) -> dict:
    """
    events: list of request_log dicts already filtered to this ip,
    each with at least {"time", "user_agent", "path"}.
    """
    matching = [e for e in events if e["ip"] == ip]
    request_count = len(matching)

    if request_count == 0:
        return {
            "ip": ip,
            "request_count": 0,
            "unique_user_agents": 0,
            "dominant_user_agent": None,
            "timing_regularity": None,
            "endpoint_spread": 0,
            "authenticity_note": "No requests observed yet from this source.",
            "concern_level": "NONE",
        }

    user_agents = [e.get("user_agent") or "unknown" for e in matching]
    unique_uas = sorted(set(user_agents))
    dominant_ua = max(set(user_agents), key=user_agents.count)

    times = sorted(e["time"] for e in matching)
    intervals = [t2 - t1 for t1, t2 in zip(times, times[1:])]
    timing_regularity = None
    if len(intervals) >= 3:
        mean_iv = statistics.mean(intervals)
        if mean_iv > 0:
            stdev_iv = statistics.pstdev(intervals)
            # coefficient of variation, inverted & clamped to 0..1:
            # low variance (very regular/metronomic intervals, typical of
            # scripted/automated traffic) -> value close to 1
            # high variance (organic/human-like timing) -> value close to 0
            cv = stdev_iv / mean_iv
            timing_regularity = round(max(0.0, min(1.0, 1.0 - min(cv, 1.0))), 2)

    endpoints = set(e["path"] for e in matching)

    concern_level = "NONE"
    notes = []
    if request_count >= 15:
        if timing_regularity is not None and timing_regularity > 0.8:
            concern_level = "ELEVATED"
            notes.append("Highly regular request timing (consistent with scripted/automated traffic)")
        if len(unique_uas) == 1 and len(endpoints) <= 1 and request_count >= 30:
            concern_level = "ELEVATED"
            notes.append("Sustained high-volume traffic to a single endpoint from one source")

    if not notes:
        notes.append("No strong automation/spoofing indicators in observed traffic")

    return {
        "ip": ip,
        "request_count": request_count,
        "unique_user_agents": len(unique_uas),
        "dominant_user_agent": dominant_ua,
        "timing_regularity": timing_regularity,
        "endpoint_spread": len(endpoints),
        "authenticity_note": "; ".join(notes),
        "concern_level": concern_level,
    }
