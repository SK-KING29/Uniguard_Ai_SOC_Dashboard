#!/usr/bin/env python3
"""
Regression tests for the SIH26145 additions: Evidence Ledger (hash chain),
Source-IP Authenticity Assessment, real Benchmark, and their wiring into
IncidentManager. Pure Python, no FastAPI/network needed - same style as
tests/test_detection_logic.py.

Run with:
    python3 tests/test_sih_extensions.py
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.ledger import EvidenceLedger, GENESIS_HASH
from detection.source_authenticity import assess_source_authenticity
from detection.benchmark import Benchmark, MIN_SAMPLES_FOR_BENCHMARK
from detection.incident_manager import IncidentManager
from detection.risk import compute_risk
from detection.engine import DetectionEngine

PASS = 0
FAIL = 0


def check(name, condition):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}")


def make_window(t, req_per_sec, unique_ips=1, concentration=0.9, burst=0.0,
                 top_ip="1.2.3.4", endpoint="/api/data"):
    return {
        "t": t, "req_per_sec": req_per_sec, "allowed_per_sec": req_per_sec,
        "bytes_per_sec": req_per_sec * 40, "unique_ips": unique_ips,
        "endpoint_concentration": concentration, "burst_indicator": burst,
        "mitigated_count": 0, "per_endpoint": {endpoint: req_per_sec}, "top_ip": top_ip,
    }


# ---------------------------------------------------------------------------
# Evidence Ledger
# ---------------------------------------------------------------------------
def test_ledger_chains_and_verifies():
    print("\n=== Test: evidence ledger chains records and verifies clean ===")
    ledger = EvidenceLedger()
    r1 = ledger.add_record(alert_id="A1", flow_id="F1", threat_class="HTTP FLOOD / DOS-LIKE",
                            confidence=0.8, risk_score=80, supporting_evidence=["x"],
                            detection_reason="x", source_ip_authenticity={"assessment": "test"})
    check("first record chains to genesis", r1["previous_record_hash"] == GENESIS_HASH)

    r2 = ledger.add_record(alert_id="A2", flow_id="F1", threat_class="HTTP FLOOD / DOS-LIKE",
                            confidence=0.9, risk_score=90, supporting_evidence=["y"],
                            detection_reason="y", source_ip_authenticity={"assessment": "test"})
    check("second record chains to first record's current hash",
          r2["previous_record_hash"] == r1["current_record_hash"])

    ok, broken_id, reason = ledger.verify_chain()
    check("clean chain verifies OK", ok is True)
    check("no broken record reported on clean chain", broken_id is None)

    status = ledger.status()
    check("status reports VERIFIED", status["integrity_status"] == "VERIFIED")
    check("record count correct", status["record_count"] == 2)


def test_ledger_detects_tampering():
    print("\n=== Test: evidence ledger detects tampering (content altered after write) ===")
    ledger = EvidenceLedger()
    ledger.add_record(alert_id="A1", flow_id="F1", threat_class="HTTP FLOOD / DOS-LIKE",
                       confidence=0.5, risk_score=50, supporting_evidence=["x"],
                       detection_reason="x", source_ip_authenticity={"assessment": "test"})
    ledger.add_record(alert_id="A2", flow_id="F1", threat_class="HTTP FLOOD / DOS-LIKE",
                       confidence=0.6, risk_score=60, supporting_evidence=["y"],
                       detection_reason="y", source_ip_authenticity={"assessment": "test"})

    ok_before, _, _ = ledger.verify_chain()
    check("chain is clean before tampering", ok_before is True)

    # Simulate someone editing a stored record's risk_score after the fact.
    ledger._tamper_for_test(0, "risk_score", 999)

    ok_after, broken_id, reason = ledger.verify_chain()
    check("tampered chain fails verification", ok_after is False)
    check("tampering correctly attributed to the altered record", broken_id == "EV-000001")
    check("reason explains evidence_hash mismatch", "evidence_hash" in reason)

    status = ledger.status()
    check("status reports TAMPER DETECTED", status["integrity_status"] == "TAMPER DETECTED")


def test_ledger_no_payloads_stored():
    print("\n=== Test: evidence ledger stores only metadata, never raw payloads ===")
    ledger = EvidenceLedger()
    r = ledger.add_record(alert_id="A1", flow_id="F1", threat_class="HTTP FLOOD / DOS-LIKE",
                           confidence=0.5, risk_score=50, supporting_evidence=["rate high"],
                           detection_reason="rate high", source_ip_authenticity={"assessment": "test"})
    forbidden_keys = {"payload", "body", "raw_packet", "packet_payload"}
    check("no payload-like keys present in stored record", forbidden_keys.isdisjoint(r.keys()))


# ---------------------------------------------------------------------------
# Source-IP Authenticity
# ---------------------------------------------------------------------------
def test_source_authenticity_flags_concentrated_burst():
    print("\n=== Test: source-IP authenticity flags concentrated/bursty traffic ===")
    w = make_window(0, req_per_sec=80, unique_ips=1, concentration=0.95, burst=0.8)
    r = assess_source_authenticity(w)
    check("concentrated single-source burst flagged as potentially spoofed",
          r["assessment"] == "Potentially Spoofed / Automated Source")
    check("indicators list is non-empty", len(r["indicators"]) >= 1)
    check("note discloses passive-only / not-proof limitation", "not proof" in r["note"])


def test_source_authenticity_normal_traffic():
    print("\n=== Test: source-IP authenticity does not flag normal multi-source traffic ===")
    w = make_window(0, req_per_sec=5, unique_ips=8, concentration=0.2, burst=0.05)
    r = assess_source_authenticity(w)
    check("calm multi-source traffic NOT flagged", r["assessment"] == "No Strong Spoofing Indicators")


def test_source_authenticity_no_data():
    print("\n=== Test: source-IP authenticity handles empty traffic without crashing ===")
    w = make_window(0, req_per_sec=0, unique_ips=0, concentration=0.0, burst=0.0)
    r = assess_source_authenticity(w)
    check("no-traffic case reports Insufficient Data", r["assessment"] == "Insufficient Data")


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------
def test_benchmark_not_benchmarked_until_enough_samples():
    print("\n=== Test: benchmark reports NOT BENCHMARKED before enough real samples ===")
    b = Benchmark()
    for i in range(MIN_SAMPLES_FOR_BENCHMARK - 1):
        b.record_window(process_seconds=0.001, req_per_sec=10, is_alert=False, now=time.time())
    stats = b.stats()
    check("not yet benchmarked", stats["benchmarked"] is False)
    check("status string is NOT BENCHMARKED", stats["status"] == "NOT BENCHMARKED")
    check("no fabricated latency figure present before threshold", "avg_detection_latency_ms" not in stats)


def test_benchmark_reports_real_measured_values():
    print("\n=== Test: benchmark reports real measured latency/throughput once warmed up ===")
    b = Benchmark()
    now = time.time()
    latencies = [0.001, 0.002, 0.0015, 0.003, 0.0012, 0.0018, 0.0025, 0.0011, 0.0022, 0.0013]
    for lat in latencies:
        b.record_window(process_seconds=lat, req_per_sec=20, is_alert=False, now=now)
    stats = b.stats(now=now)
    check("benchmarked once enough samples collected", stats["benchmarked"] is True)
    expected_avg_ms = round(sum(latencies) / len(latencies) * 1000, 2)
    check("avg latency matches real measured average (not fabricated)",
          abs(stats["avg_detection_latency_ms"] - expected_avg_ms) < 0.01)
    check("throughput reflects real recorded req/s", stats["throughput_requests_per_sec"] == 20.0)
    check("measurement scope discloses HTTP-only limitation",
          "packet" in stats["measurement_scope"].lower())


def test_benchmark_alerts_per_sec_uses_real_alert_events():
    print("\n=== Test: benchmark alerts/sec reflects real recorded alert windows ===")
    b = Benchmark()
    now = time.time()
    for i in range(MIN_SAMPLES_FOR_BENCHMARK):
        b.record_window(process_seconds=0.001, req_per_sec=5, is_alert=(i % 2 == 0), now=now)
    stats = b.stats(now=now)
    check("alerts_per_sec is a real non-negative measured rate", stats["alerts_per_sec"] >= 0)


# ---------------------------------------------------------------------------
# Integration: IncidentManager + EvidenceLedger + Source Authenticity
# ---------------------------------------------------------------------------
def test_incident_manager_writes_to_ledger_when_attached():
    print("\n=== Test: IncidentManager writes evidence records when a ledger is attached ===")
    ledger = EvidenceLedger()
    engine = DetectionEngine()
    im = IncidentManager(ledger=ledger)
    t = 0.0
    for i in range(40):
        w = make_window(t, 2 + (i % 3) * 0.2)
        a = engine.analyze(w); r = compute_risk(w, a); engine.update_baseline(w); im.process_window(w, a, r)
        t += 1
    for i in range(10):
        w = make_window(t, 60, unique_ips=1, concentration=0.95, burst=0.6, top_ip="203.0.113.7")
        a = engine.analyze(w); r = compute_risk(w, a); im.process_window(w, a, r)
        t += 1

    check("incident opened", im.active_incident_id is not None)
    check("ledger received at least one record", len(ledger.records) >= 1)

    inc = im.incidents[im.active_incident_id]
    check("incident carries evidence_hash", "evidence_hash" in inc and inc["evidence_hash"])
    check("incident carries previous_record_hash", "previous_record_hash" in inc)
    check("incident carries current_record_hash", "current_record_hash" in inc)
    check("incident integrity_status is VERIFIED", inc["integrity_status"] == "VERIFIED")
    check("incident carries standardized threat_class", inc["threat_class"] == "HTTP FLOOD / DOS-LIKE")
    check("incident carries confidence in [0,1]", 0.0 <= inc["confidence"] <= 1.0)
    check("incident carries source_ip_authenticity assessment",
          "assessment" in inc["source_ip_authenticity"])
    check("incident destination_ip is honestly N/A (no packet capture)",
          "N/A" in inc["destination_ip"])

    ok, broken_id, reason = ledger.verify_chain()
    check("full ledger chain still verifies after incident lifecycle", ok is True)


def test_incident_manager_without_ledger_unaffected():
    print("\n=== Test: IncidentManager with NO ledger (default) behaves exactly as before ===")
    engine = DetectionEngine()
    im = IncidentManager()  # no ledger - matches every existing test_detection_logic.py call
    t = 0.0
    for i in range(40):
        w = make_window(t, 2 + (i % 3) * 0.2)
        a = engine.analyze(w); r = compute_risk(w, a); engine.update_baseline(w); im.process_window(w, a, r)
        t += 1
    for i in range(10):
        w = make_window(t, 60, unique_ips=1, concentration=0.95, burst=0.6, top_ip="203.0.113.7")
        a = engine.analyze(w); r = compute_risk(w, a); im.process_window(w, a, r)
        t += 1
    check("incident still opens without a ledger attached", im.active_incident_id is not None)
    inc = im.incidents[im.active_incident_id]
    check("standardized fields still present even with no ledger", "threat_class" in inc)
    check("no evidence_hash written when no ledger attached", "evidence_hash" not in inc)


def test_mitigation_path_labeled_not_sih_passive():
    print("\n=== Test: mitigation is explicitly labeled as NOT the SIH passive path ===")
    ledger = EvidenceLedger()
    engine = DetectionEngine()
    im = IncidentManager(ledger=ledger)
    t = 0.0
    for i in range(40):
        w = make_window(t, 2.0)
        a = engine.analyze(w); r = compute_risk(w, a); engine.update_baseline(w); im.process_window(w, a, r)
        t += 1
    for i in range(10):
        w = make_window(t, 60, unique_ips=1, concentration=0.95, burst=0.6, top_ip="203.0.113.7")
        a = engine.analyze(w); r = compute_risk(w, a); im.process_window(w, a, r)
        t += 1
    im.apply_mitigation("block_source", "test: judge blocked source")
    inc = im.incidents[im.active_incident_id]
    check("mitigation_path explicitly marked ACTIVE_APPLICATION_LAYER",
          inc["mitigation_path"] == "ACTIVE_APPLICATION_LAYER")


if __name__ == "__main__":
    test_ledger_chains_and_verifies()
    test_ledger_detects_tampering()
    test_ledger_no_payloads_stored()
    test_source_authenticity_flags_concentrated_burst()
    test_source_authenticity_normal_traffic()
    test_source_authenticity_no_data()
    test_benchmark_not_benchmarked_until_enough_samples()
    test_benchmark_reports_real_measured_values()
    test_benchmark_alerts_per_sec_uses_real_alert_events()
    test_incident_manager_writes_to_ledger_when_attached()
    test_incident_manager_without_ledger_unaffected()
    test_mitigation_path_labeled_not_sih_passive()

    print(f"\n{'='*50}")
    print(f"RESULTS: {PASS} passed, {FAIL} failed")
    print(f"{'='*50}")
    if FAIL > 0:
        sys.exit(1)
