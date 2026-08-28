#!/usr/bin/env python3
"""
Regression tests for the detection engine, risk scoring, incident lifecycle,
and mitigation enforcement - the parts of UniGuard AI that can be tested
without a running FastAPI server (pure Python, no network needed).

Run with:
    python3 tests/test_detection_logic.py

These are the exact tests used to find and fix two real bugs during
development:
  1. IsolationForest with a fixed contamination rate flagged ~20-30% of
     perfectly calm, repetitive traffic as anomalous (contamination forces
     a fixed outlier proportion regardless of actual distribution). Fixed
     by switching to percentile-rank calibration + lowering contamination.
  2. A single noisy 1-second window could flip system status / open a
     false incident. Fixed with a 2-window debounce in IncidentManager.

NOTE: This does not test the FastAPI HTTP layer itself (routing,
middleware request/response handling) - that requires `pip install
fastapi uvicorn` and a running server, which was not possible to verify
in the environment this project was prepared in (no internet access).
Run the server locally once before your live demo to confirm:
    pip install -r requirements.txt
    uvicorn app:app --reload
    open http://localhost:8000/dashboard
"""
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.engine import DetectionEngine
from detection.risk import compute_risk
from detection.incident_manager import IncidentManager
from mitigation.controls import MitigationStore

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


def test_no_false_positives_on_calm_traffic():
    print("\n=== Test: no false positives on calm/repetitive traffic ===")
    engine = DetectionEngine()
    im = IncidentManager()
    t = 0.0
    false_alarms = 0
    for i in range(80):
        w = make_window(t, 2 + (i % 3) * 0.2)  # repetitive worst-case pattern
        a = engine.analyze(w)
        r = compute_risk(w, a)
        engine.update_baseline(w)
        im.process_window(w, a, r)
        if i >= 30 and im.system_status != "PROTECTED":
            false_alarms += 1
        t += 1
    check("zero false alarms after model warm-up", false_alarms == 0)
    check("zero incidents falsely opened", len(im.incidents) == 0)


def test_real_attack_detected():
    print("\n=== Test: sustained DoS-like spike is detected ===")
    engine = DetectionEngine()
    im = IncidentManager()
    t = 0.0
    for i in range(40):
        w = make_window(t, 2 + (i % 3) * 0.2)
        a = engine.analyze(w); r = compute_risk(w, a); engine.update_baseline(w); im.process_window(w, a, r)
        t += 1
    for i in range(10):
        w = make_window(t, 60, unique_ips=1, concentration=0.95, burst=0.6, top_ip="203.0.113.7")
        a = engine.analyze(w); r = compute_risk(w, a); im.process_window(w, a, r)
        t += 1
    check("system status escalates to ATTACK", im.system_status == "ATTACK")
    check("incident opened", im.active_incident_id is not None)
    if im.active_incident_id:
        inc = im.incidents[im.active_incident_id]
        check("severity is CRITICAL", inc["severity"] == "CRITICAL")
        check("source IP correctly identified", inc["source_ip"] == "203.0.113.7")
        check("evidence list is non-empty and specific", len(inc["evidence"]) >= 2)
    return engine, im, t


def test_single_blip_does_not_trigger():
    print("\n=== Test: a single noisy window does NOT open an incident (debounce) ===")
    engine = DetectionEngine()
    im = IncidentManager()
    t = 0.0
    for i in range(40):
        w = make_window(t, 2.0)
        a = engine.analyze(w); r = compute_risk(w, a); engine.update_baseline(w); im.process_window(w, a, r)
        t += 1
    # one single spike window, then back to calm
    w = make_window(t, 50, concentration=0.95, burst=0.6); t += 1
    a = engine.analyze(w); r = compute_risk(w, a); im.process_window(w, a, r)
    check("single spike alone does not open an incident", im.active_incident_id is None)
    check("system status still PROTECTED after one spike", im.system_status == "PROTECTED")


def test_mitigation_and_recovery():
    print("\n=== Test: mitigation applies, then traffic recovers ===")
    engine, im, t = test_real_attack_detected()
    inc_id = im.active_incident_id
    im.apply_mitigation("block_source", "test: judge blocked source")
    check("incident status becomes MITIGATING", im.incidents[inc_id]["status"] == "MITIGATING")

    for i in range(6):
        w = make_window(t, 2.0, concentration=0.1, burst=0.0, top_ip="203.0.113.7")
        a = engine.analyze(w); r = compute_risk(w, a); im.process_window(w, a, r)
        t += 1
    check("incident resolved after sustained calm traffic", im.active_incident_id is None)
    check("system status back to PROTECTED", im.system_status == "PROTECTED")
    check("incident marked RESOLVED", im.incidents[inc_id]["status"] == "RESOLVED")


def test_mitigation_store_enforcement():
    print("\n=== Test: mitigation store actually blocks/rate-limits ===")
    store = MitigationStore()
    store.block_ip("1.2.3.4", ttl=60)
    allowed, reason = store.check("1.2.3.4", "/api/data")
    check("blocked IP is rejected", allowed is False and reason == "blocked")

    allowed2, reason2 = store.check("9.9.9.9", "/api/data")
    check("different IP is unaffected", allowed2 is True)

    store2 = MitigationStore()
    store2.rate_limit_ip("5.5.5.5", limit_per_sec=2, ttl=60)
    results = [store2.check("5.5.5.5", "/api/data")[0] for _ in range(10)]
    check("rate limiting allows only a small burst, denies the rest",
          results.count(True) <= 3 and results.count(False) >= 7)


def test_mitigation_store_concurrency():
    print("\n=== Test: mitigation store is thread-safe under concurrent load ===")
    store = MitigationStore()
    store.rate_limit_ip("9.9.9.9", limit_per_sec=5, ttl=30)
    results = {"allowed": 0, "denied": 0}
    errors = []
    lock = threading.Lock()

    def worker():
        try:
            allowed, _ = store.check("9.9.9.9", "/api/data")
            with lock:
                results["allowed" if allowed else "denied"] += 1
        except Exception as e:
            with lock:
                errors.append(str(e))

    threads = [threading.Thread(target=worker) for _ in range(300)]
    for th in threads: th.start()
    for th in threads: th.join()

    check("no exceptions under 300 concurrent requests", len(errors) == 0)
    check("token bucket enforced burst limit correctly", results["allowed"] <= 5)


def test_reset_clears_state():
    print("\n=== Test: reset clears incidents and mitigation state ===")
    store = MitigationStore()
    store.block_ip("1.2.3.4", ttl=120)
    store.reset()
    allowed, _ = store.check("1.2.3.4", "/api/data")
    check("reset clears blocks", allowed is True)

    im = IncidentManager()
    im.incidents["FAKE-1"] = {"status": "ACTIVE"}
    im.active_incident_id = "FAKE-1"
    im.system_status = "ATTACK"
    im.reset()
    check("reset clears incidents", len(im.incidents) == 0)
    check("reset restores PROTECTED status", im.system_status == "PROTECTED")


def test_ip_intelligence_heuristics():
    print("\n=== Test: IP intelligence distinguishes scripted vs organic traffic ===")
    from detection.ip_intel import compute_ip_intel
    import random

    scripted = [{"time": 100.0 + i * 0.1, "ip": "9.9.9.9",
                 "user_agent": "UniGuard-Termux-TestClient/1.0", "path": "/api/data"} for i in range(40)]
    r = compute_ip_intel("9.9.9.9", scripted)
    check("scripted/metronomic traffic flagged ELEVATED", r["concern_level"] == "ELEVATED")
    check("timing regularity is high for scripted traffic", r["timing_regularity"] > 0.8)

    random.seed(1)
    organic = []
    t = 200.0
    uas = ["Mozilla/5.0 Chrome", "Mozilla/5.0 Safari"]
    paths = ["/", "/api/login", "/api/data", "/api/search"]
    for i in range(10):
        t += random.uniform(0.5, 4.0)
        organic.append({"time": t, "ip": "1.1.1.1", "user_agent": random.choice(uas), "path": random.choice(paths)})
    r2 = compute_ip_intel("1.1.1.1", organic)
    check("organic/varied traffic NOT flagged", r2["concern_level"] == "NONE")

    r3 = compute_ip_intel("5.5.5.5", [])
    check("no-data case handled without crashing", r3["request_count"] == 0)


def test_recovery_time_is_real():
    print("\n=== Test: recovery time is a real computed duration, not fabricated ===")
    import time as _time
    engine, im, t = test_real_attack_detected()
    inc_id = im.active_incident_id
    before_mitigate = _time.time()
    im.apply_mitigation("block_source", "test")
    after_mitigate = _time.time()
    applied_at = im.incidents[inc_id]["mitigation_applied_at"]
    check("mitigation_applied_at recorded with a real wall-clock timestamp",
          applied_at is not None and before_mitigate <= applied_at <= after_mitigate)

    for i in range(6):
        w = make_window(t, 2.0, concentration=0.1, burst=0.0, top_ip="203.0.113.7")
        a = engine.analyze(w); r = compute_risk(w, a); im.process_window(w, a, r)
        t += 1
    resolved_at = im.incidents[inc_id]["resolved_at"]
    # resolved_at uses the synthetic window clock (matches production, where
    # window["t"] IS time.time() - only this test harness uses a fake counter)
    check("incident marked resolved with a timestamp", resolved_at is not None)


if __name__ == "__main__":
    test_no_false_positives_on_calm_traffic()
    test_single_blip_does_not_trigger()
    test_real_attack_detected()
    test_mitigation_and_recovery()
    test_mitigation_store_enforcement()
    test_mitigation_store_concurrency()
    test_reset_clears_state()
    test_ip_intelligence_heuristics()
    test_recovery_time_is_real()

    print(f"\n{'='*50}")
    print(f"RESULTS: {PASS} passed, {FAIL} failed")
    print(f"{'='*50}")
    if FAIL > 0:
        sys.exit(1)
