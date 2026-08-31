"""
Source-IP Authenticity Assessment.

Passive, application-layer heuristic only. This does NOT claim to
identify a real attacker or prove spoofing - passive monitoring cannot
guarantee that. It flags patterns that are commonly associated with
automated/spoofed-style traffic, using only real fields already computed
from the live traffic window in app.py (unique_ips, req_per_sec,
burst_indicator, endpoint_concentration) - no new data source.

Packet-level spoofing indicators (TTL anomalies, IP-ID sequence analysis,
TCP fingerprint inconsistency) require raw packet capture, which this
HTTP-application-layer build does not have. That capability is Architecture
Ready / Not Currently Implemented here - see /api/sih-alignment.
"""

NOTE = (
    "Passive, application-layer assessment only - not proof of attacker "
    "identity. Based on source concentration and traffic-burst patterns "
    "from real observed requests. Packet-level spoofing indicators "
    "(TTL/IP-ID/TCP-fingerprint anomalies) require raw packet capture and "
    "are Architecture Ready / Not Currently Implemented in this "
    "HTTP-application-layer build."
)


def assess_source_authenticity(window: dict) -> dict:
    indicators = []

    unique_ips = window.get("unique_ips", 0) or 0
    req_per_sec = window.get("req_per_sec", 0.0) or 0.0
    burst = window.get("burst_indicator", 0.0) or 0.0
    concentration = window.get("endpoint_concentration", 0.0) or 0.0

    if unique_ips <= 2 and req_per_sec > 15:
        indicators.append(
            f"High request volume ({req_per_sec:.1f} req/s) concentrated from "
            f"only {unique_ips} source IP(s)"
        )
    if burst > 0.6:
        indicators.append(
            f"Sudden traffic burst (burst indicator {burst:.2f}) inconsistent "
            "with gradual, organic multi-source traffic growth"
        )
    if concentration > 0.7 and unique_ips <= 3:
        indicators.append(
            "Traffic heavily concentrated on a single endpoint from very few sources"
        )

    if indicators:
        assessment = "Potentially Spoofed / Automated Source"
    elif unique_ips > 0:
        assessment = "No Strong Spoofing Indicators"
    else:
        assessment = "Insufficient Data"

    return {
        "assessment": assessment,
        "indicators": indicators,
        "note": NOTE,
    }
