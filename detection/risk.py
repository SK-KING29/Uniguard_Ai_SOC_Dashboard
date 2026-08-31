"""
Risk engine. Every number here is derived from the current traffic window
and the detection engine's output - nothing is hardcoded or randomized.
"""

def compute_risk(window, analysis):
    rate_component = min(40.0, analysis["baseline_deviation_pct"] / 10.0)
    anomaly_component = min(30.0, analysis["anomaly_score"] * 0.3)
    burst_component = min(15.0, window["burst_indicator"] * 15.0)
    concentration_component = min(15.0, window["endpoint_concentration"] * 15.0)

    score = round(min(100.0, rate_component + anomaly_component +
                       burst_component + concentration_component), 1)

    if score >= 75:
        severity, status = "CRITICAL", "ATTACK"
    elif score >= 50:
        severity, status = "HIGH", "SUSPICIOUS"
    elif score >= 25:
        severity, status = "MEDIUM", "SUSPICIOUS"
    else:
        severity, status = "LOW", "NORMAL"

    evidence = []
    if analysis["baseline_deviation_pct"] > 50:
        evidence.append(
            f"Request rate {analysis['baseline_deviation_pct']:.0f}% above baseline "
            f"({window['req_per_sec']:.1f} req/s vs {analysis['baseline_rate']:.1f} req/s baseline)"
        )
    if analysis["model_ready"] and analysis["anomaly_score"] > 40:
        evidence.append(
            f"Isolation Forest anomaly score {analysis['anomaly_score']:.0f}/100 "
            f"- traffic pattern statistically abnormal vs recent history"
        )
    if window["burst_indicator"] > 0.5:
        evidence.append("Sudden traffic burst detected within a 1-second window")
    if window["endpoint_concentration"] > 0.5:
        evidence.append("Traffic abnormally concentrated on a small number of endpoints")
    if window["unique_ips"] <= 2 and window["req_per_sec"] > 15:
        evidence.append("High request volume from a very small number of source IPs (DoS-like pattern)")
    if not evidence:
        evidence.append("Traffic within expected range - no anomaly indicators active")

    return {
        "risk_score": score,
        "severity": severity,
        "status": status,
        "components": {
            "rate_anomaly": round(rate_component / 40 * 100),
            "baseline_deviation": round(anomaly_component / 30 * 100),
            "traffic_burst": round(burst_component / 15 * 100),
            "endpoint_concentration": round(concentration_component / 15 * 100),
        },
        "evidence": evidence,
    }
