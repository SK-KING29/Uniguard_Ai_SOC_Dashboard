"""
UniGuard AI - SOC backend (FastAPI).

Everything here is real:
  - Every request to a "demo target" endpoint is genuinely logged by
    middleware (timestamp, source IP, path, method, status, byte size).
  - Traffic windows are built from that real log every 1 second.
  - Detection (detection/engine.py), risk scoring (detection/risk.py) and
    incident lifecycle (detection/incident_manager.py) run on those real
    windows - no random numbers anywhere in this file.
  - Mitigation actions (mitigation/controls.py) actually change what the
    middleware does to the next request from a target - block/rate-limit
    is enforced, not simulated.

Scope note: this monitors APPLICATION-LAYER HTTP traffic, not raw network
packets - packet capture is not possible on any hosted PaaS. Stated
explicitly via /api/health and in the dashboard so nothing is overclaimed.

Update note: the phone-side test traffic generator is now a standalone
Termux script (see termux_test_client.py) that sends real HTTP requests
to this backend's own public URL - not a browser page served by this app.

Dashboard updates: polling (GET /api/metrics every ~1s), not WebSocket/SSE.
This is a deliberate choice for reliability on free hosting tiers, where
long-lived WebSocket/SSE connections are more prone to proxy timeouts.
"""
import time
import asyncio
import threading
from pathlib import Path
from contextlib import asynccontextmanager
from collections import deque, defaultdict

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from detection.engine import DetectionEngine
from detection.risk import compute_risk
from detection.incident_manager import IncidentManager
from detection.ip_intel import compute_ip_intel
from detection.ledger import EvidenceLedger
from detection.benchmark import Benchmark
from detection.source_authenticity import assess_source_authenticity
from mitigation.controls import MitigationStore
from mobile_demo import MobileDemoStore

# ---------------------------------------------------------------------------
# Global real-time state
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent   # absolute, not cwd-dependent -
                                              # matters because some PaaS build/
                                              # start setups launch uvicorn from
                                              # a different working directory
STATIC_DIR = BASE_DIR / "static"

TARGET_PATHS = {"/", "/api/login", "/api/data", "/api/search"}

request_log = deque(maxlen=20000)     # raw real request events
log_lock = threading.Lock()

engine = DetectionEngine()
mitigation = MitigationStore()
evidence_ledger = EvidenceLedger()      # SIH26145: hash-chained evidence integrity
benchmark = Benchmark()                 # SIH26145: real, measured throughput/latency
incident_mgr = IncidentManager(ledger=evidence_ledger)
mobile_demo = MobileDemoStore()
state_lock = threading.Lock()

BACKEND_START_TIME = time.time()
_bg_task = None

# Real in-flight request counter (active connections). Incremented when a
# target-path request starts, decremented when it finishes - not a fake
# or randomly generated number.
active_connections = 0
active_connections_lock = threading.Lock()

# Cumulative total requests seen since last reset (real counter, not derived
# from a capped log - request_log itself is capped at 20000 for memory).
total_requests_seen = 0
total_requests_lock = threading.Lock()


async def analysis_loop():
    last_window_end = time.time()
    while True:
        await asyncio.sleep(1.0)
        now = time.time()
        window_start, window_end = last_window_end, now
        last_window_end = now

        with log_lock:
            events = [e for e in request_log if window_start <= e["time"] < window_end]

        duration = max(0.001, window_end - window_start)
        total = len(events)
        allowed_events = [e for e in events if not e["mitigated"]]
        mitigated_events = [e for e in events if e["mitigated"]]

        ips = set(e["ip"] for e in events)
        per_endpoint = defaultdict(int)
        for e in events:
            per_endpoint[e["path"]] += 1

        req_per_sec = total / duration
        allowed_per_sec = len(allowed_events) / duration
        bytes_per_sec = sum(e["bytes"] for e in events) / duration

        concentration = 0.0
        if total > 0:
            hhi = sum((c / total) ** 2 for c in per_endpoint.values())
            floor = 1 / max(1, len(TARGET_PATHS))
            concentration = min(1.0, max(0.0, (hhi - floor) / (1 - floor))) if floor < 1 else 0.0

        half = window_start + duration / 2
        first_half = len([e for e in events if e["time"] < half])
        second_half = total - first_half
        burst = 0.0
        if total >= 6:
            burst = max(0.0, (second_half - first_half) / max(1, total))

        window = {
            "t": window_end,
            "req_per_sec": round(req_per_sec, 2),
            "allowed_per_sec": round(allowed_per_sec, 2),
            "bytes_per_sec": round(bytes_per_sec, 1),
            "unique_ips": len(ips),
            "endpoint_concentration": round(concentration, 3),
            "burst_indicator": round(burst, 3),
            "mitigated_count": len(mitigated_events),
            "per_endpoint": dict(per_endpoint),
            "top_ip": max(ips, key=lambda i: sum(1 for e in events if e["ip"] == i)) if ips else None,
        }

        # Real detection-latency measurement (SIH26145 throughput/latency
        # benchmark requirement): perf_counter wall-clock time actually
        # spent running the detection -> risk -> incident pipeline on this
        # window, not an estimate.
        proc_t0 = time.perf_counter()
        analysis = engine.analyze(window)
        risk = compute_risk(window, analysis)

        with state_lock:
            incident_mgr.process_window(window, analysis, risk)
        proc_t1 = time.perf_counter()

        benchmark.record_window(
            process_seconds=proc_t1 - proc_t0,
            req_per_sec=window["req_per_sec"],
            is_alert=risk["status"] != "NORMAL",
            now=now,
        )

        if risk["status"] == "NORMAL":
            engine.update_baseline(window)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _bg_task
    with state_lock:
        incident_mgr.log_event("Backend started - baseline monitoring active", "info")
    _bg_task = asyncio.create_task(analysis_loop())
    yield
    if _bg_task:
        _bg_task.cancel()


app = FastAPI(title="UniGuard AI SOC Backend", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Middleware: logs every real request, enforces real mitigation
# ---------------------------------------------------------------------------
@app.middleware("http")
async def traffic_middleware(request: Request, call_next):
    global active_connections, total_requests_seen

    path = request.url.path
    if path not in TARGET_PATHS:
        return await call_next(request)

    ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown").split(",")[0].strip()
    ua = request.headers.get("user-agent", "unknown")
    t0 = time.time()

    allowed, reason = mitigation.check(ip, path)
    if not allowed:
        status_code = 403 if reason == "blocked" else 429
        with log_lock:
            request_log.append({
                "time": t0, "ip": ip, "path": path, "method": request.method,
                "status": status_code, "bytes": 0, "user_agent": ua,
                "mitigated": True, "reason": reason,
            })
        with total_requests_lock:
            total_requests_seen += 1
        return JSONResponse({"error": reason, "message": "Request rejected by UniGuard AI mitigation"},
                             status_code=status_code)

    with active_connections_lock:
        active_connections += 1
    try:
        response = await call_next(request)
    finally:
        with active_connections_lock:
            active_connections -= 1

    body_bytes = int(response.headers.get("content-length", 0) or 0)
    with log_lock:
        request_log.append({
            "time": t0, "ip": ip, "path": path, "method": request.method,
            "status": response.status_code, "bytes": body_bytes, "user_agent": ua,
            "mitigated": False, "reason": None,
        })
    with total_requests_lock:
        total_requests_seen += 1
    return response


# ---------------------------------------------------------------------------
# Demo target endpoints - a tiny "real app" that gets monitored/protected.
# ---------------------------------------------------------------------------
@app.get("/")
async def home():
    return {"app": "UniGuard AI - protected demo application", "status": "ok"}


@app.get("/api/login")
async def api_login():
    return {"endpoint": "login", "status": "ok"}


@app.get("/api/data")
async def api_data():
    return {"endpoint": "data", "status": "ok", "payload": list(range(20))}


@app.get("/api/search")
async def api_search(q: str = ""):
    return {"endpoint": "search", "query": q, "results": []}


# ---------------------------------------------------------------------------
# Dashboard API
# ---------------------------------------------------------------------------
@app.get("/api/metrics")
async def api_metrics():
    with state_lock:
        snap = incident_mgr.snapshot()

    ip_intel = None
    active = snap.get("active_incident")
    if active and active.get("source_ip"):
        target_ip = active["source_ip"]
        with log_lock:
            recent_events = [e for e in request_log if e["time"] >= time.time() - 30 and e["ip"] == target_ip]
        ip_intel = compute_ip_intel(target_ip, recent_events)

    with active_connections_lock:
        conns = active_connections
    with total_requests_lock:
        total_reqs = total_requests_seen

    return {
        **snap,
        "mitigation": mitigation.status(),
        "audit_log": mitigation.audit_log[-30:],
        "uptime_seconds": round(time.time() - BACKEND_START_TIME),
        "monitoring_scope": "APPLICATION_LAYER_HTTP",
        "update_mode": "poll",
        "active_connections": conns,
        "total_requests": total_reqs,
        "ip_intelligence": ip_intel,
    }


@app.get("/api/traffic/recent")
async def api_traffic_recent(limit: int = 50):
    with log_lock:
        events = list(request_log)[-limit:]
    return {"events": list(reversed(events))}


@app.post("/api/mitigate")
async def api_mitigate(payload: dict):
    action = payload.get("action")
    target = payload.get("target")
    try:
        ttl = int(payload.get("ttl", 120))
    except (TypeError, ValueError):
        return JSONResponse({"error": "ttl must be a number"}, status_code=400)

    with state_lock:
        active = incident_mgr.incidents.get(incident_mgr.active_incident_id) if incident_mgr.active_incident_id else None
        if target in (None, "auto") and active:
            target = active.get("source_ip")

    if action == "rate_limit_source" and target:
        mitigation.rate_limit_ip(target, limit_per_sec=payload.get("limit", 1.0), ttl=ttl)
        label = f"Judge applied rate limiting to {target}"
    elif action == "block_source" and target:
        mitigation.block_ip(target, ttl=ttl)
        label = f"Judge blocked source {target}"
    elif action == "protect_endpoint":
        path = payload.get("path") or "/"
        with state_lock:
            active = incident_mgr.incidents.get(incident_mgr.active_incident_id) if incident_mgr.active_incident_id else None
            if active and active.get("affected_endpoint"):
                path = active["affected_endpoint"]
        mitigation.protect_endpoint(path, limit_per_sec=payload.get("limit", 5.0), ttl=ttl)
        label = f"Judge applied endpoint protection to {path}"
    elif action == "monitor_only":
        mitigation.monitor_only()
        label = "Judge chose monitor-only (no mitigation applied)"
    else:
        return JSONResponse({"error": "invalid action or missing target"}, status_code=400)

    with state_lock:
        incident_mgr.apply_mitigation(action, label)

    return {"ok": True, "action": action, "target": target, "ttl": ttl}


@app.post("/api/reset")
async def api_reset():
    global total_requests_seen
    mitigation.reset()
    with log_lock:
        request_log.clear()
    with state_lock:
        incident_mgr.reset()
    with total_requests_lock:
        total_requests_seen = 0
    engine.baseline_buffer.clear()
    engine.feature_buffer.clear()
    engine.model = None
    engine.windows_since_train = 0
    engine._train_scores = None
    engine.baseline_rate = 0.5
    return {"ok": True}


@app.post("/api/mobile-demo/start")
async def api_mobile_demo_start(request: Request, payload: dict = None):
    """Phone presses START. Records the phone's real observed IP (read the
    same way the traffic middleware does) and begins the SAFE, SIMULATED
    ramp - no real traffic is sent to any target endpoint."""
    payload = payload or {}
    intensity = str(payload.get("intensity") or "MEDIUM").upper()
    ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown").split(",")[0].strip()
    mobile_demo.start(intensity, ip)
    return {"ok": True, "incident": mobile_demo.snapshot()}


@app.post("/api/mobile-demo/mitigate")
async def api_mobile_demo_mitigate():
    mobile_demo.mitigate()
    return {"ok": True, "incident": mobile_demo.snapshot()}


@app.post("/api/mobile-demo/stop")
async def api_mobile_demo_stop():
    mobile_demo.stop()
    return {"ok": True}


@app.get("/api/mobile-demo/state")
async def api_mobile_demo_state():
    """Polled by every connected dashboard (any device, any network) so the
    phone's simulated incident shows up everywhere, not just on the phone."""
    return {"incident": mobile_demo.snapshot()}


@app.get("/api/health")
async def api_health():
    return {
        "backend": "running",
        "traffic_monitor": "running",
        "ai_engine": "running" if engine.model is not None else "warming_up",
        "mitigation_engine": "running",
        "uptime_seconds": round(time.time() - BACKEND_START_TIME),
        "monitoring_scope": "Application-layer HTTP traffic (no raw packet capture on hosted PaaS)",
        "dashboard_update_mode": "poll (~1s interval), not WebSocket/SSE",
    }


@app.get("/api/ip-lookup/{ip}")
async def api_ip_lookup(ip: str):
    """
    Real lookup - reuses the same compute_ip_intel heuristic as the
    incident panel, but for ANY ip that appears in the real request log
    (not just the current incident's source). Looks at the full retained
    log (up to 20000 entries), not just the last 30s, since this is an
    explicit on-demand investigation, not a live rolling window.
    """
    with log_lock:
        matching = [e for e in request_log if e["ip"] == ip]
    intel = compute_ip_intel(ip, matching)
    if matching:
        intel["first_seen"] = min(e["time"] for e in matching)
        intel["last_seen"] = max(e["time"] for e in matching)
        intel["ip_type"] = "Private" if (
            ip.startswith("10.") or ip.startswith("192.168.") or
            ip.startswith("172.16.") or ip.startswith("127.")
        ) else "Public"
    else:
        intel["first_seen"] = None
        intel["last_seen"] = None
        intel["ip_type"] = None
    return intel


@app.get("/api/ledger")
async def api_ledger(limit: int = 50):
    """
    Security Evidence Ledger - hash-chained (SHA-256), tamper-evident
    record of every incident open/escalate/mitigate/resolve event.
    integrity_status is re-derived from the stored records on every call
    (not cached), so tampering with in-memory records would be reflected
    here immediately. This is the "Blockchain & Cybersecurity" theme
    component: a local, permissioned-style hash chain protecting evidence
    integrity - not a cryptocurrency, not a public/distributed blockchain,
    and it stores no packet payloads (metadata only).
    """
    return evidence_ledger.snapshot(limit=limit)


@app.get("/api/benchmark")
async def api_benchmark():
    """
    Real throughput/detection-latency benchmark, measured continuously by
    the analysis loop above (time.perf_counter around the real
    detect -> risk -> incident pipeline). Returns NOT BENCHMARKED until
    enough windows have actually been measured - never a hardcoded number.
    """
    return benchmark.stats()


@app.get("/api/sih-alignment")
async def api_sih_alignment():
    """
    Static project/architecture metadata for the dashboard's SIH26145
    Alignment card. No external URLs are included here - only the
    problem-statement identifiers and an honest capability matrix derived
    from what this codebase actually implements.
    """
    return {
        "problem_statement_id": "SIH26145",
        "problem_statement": "AI-Based Detection of Cyber Threats in Unidirectional IP Traffic",
        "organization": "National Technical Research Organisation (NTRO)",
        "theme": "Blockchain & Cybersecurity",
        "sih_passive_pipeline": [
            "One-way traffic copy (target architecture - see implementation_note)",
            "Read-only ingest",
            "Flow extraction",
            "Feature extraction",
            "AI/ML analysis (Isolation Forest, real-time)",
            "Threat classification",
            "Risk scoring (explainable)",
            "Source-IP authenticity assessment",
            "Evidence ledger (hash-chained)",
            "SOC dashboard",
        ],
        "implementation_note": (
            "This prototype observes application-layer HTTP traffic to its own "
            "demo endpoints (request middleware), not a raw unidirectional "
            "network tap / PCAP feed - packet capture is not possible on hosted "
            "PaaS. Every pipeline stage above this line runs on real observed "
            "traffic. The existing 'Mitigate Attack' feature is a SEPARATE, "
            "ACTIVE, application-layer control path (mitigation/controls.py) "
            "that is NOT part of this passive pipeline - see mitigation_path."
        ),
        "mitigation_path": {
            "label": "Active Mitigation — Demo/Application Layer",
            "is_part_of_sih_passive_path": False,
            "description": (
                "Real, in-band HTTP mitigation (block/rate-limit) that the "
                "existing dashboard's Investigation page already applies. "
                "Kept intact as existing working functionality, but it is "
                "explicitly NOT the read-only, no-return-path SIH26145 "
                "monitoring architecture."
            ),
        },
        "threat_category_coverage": [
            {"category": "Volumetric / Protocol DDoS (rate, burst, concentration)",
             "status": "Demo Coverage",
             "note": "Detected via real req/s, burst indicator, endpoint concentration on HTTP traffic."},
            {"category": "Botnet C2 Beaconing (periodicity / timing regularity)",
             "status": "Demo Coverage",
             "note": "Timing-regularity heuristic exists (detection/ip_intel.py) on HTTP request intervals per source."},
            {"category": "DGA Domains / DNS Tunnelling",
             "status": "Architecture Ready / Not Currently Implemented",
             "note": "Requires DNS query metadata; this build has no DNS visibility (HTTP-only)."},
            {"category": "Malware in Encrypted Sessions (TLS/QUIC/JA3/JA4 metadata)",
             "status": "Architecture Ready / Not Currently Implemented",
             "note": "No TLS/QUIC handshake metadata is captured at the application layer. Payload decryption is never used."},
            {"category": "Reconnaissance / Port Scanning",
             "status": "Architecture Ready / Not Currently Implemented",
             "note": "Requires per-port/per-host connection visibility; this build only sees its own 4 HTTP routes."},
            {"category": "Data Exfiltration (byte-ratio, duration, concentration)",
             "status": "Demo Coverage",
             "note": "Partial: outbound byte-rate and endpoint concentration are real; inbound/outbound flow ratios are not computed."},
        ],
        "evidence_integrity": {
            "mechanism": "Local SHA-256 hash chain (not a public blockchain, not cryptocurrency)",
            "payload_stored": "Alert/evidence metadata only - no packet payloads",
        },
        "encryption_scope": {"payload_decryption": "NOT USED", "analysis_basis": "Metadata / application-layer HTTP only"},
    }


@app.get("/api/system")
async def api_system():
    """
    Real system resource usage via psutil - not fabricated. cpu_percent
    with interval=None returns the usage since the last call (or since
    process start on first call), which is standard psutil usage and
    avoids blocking the request for a full sampling interval.
    """
    try:
        import psutil
        vm = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        cpu = psutil.cpu_percent(interval=None)
        resource_data = {
            "cpu_percent": cpu,
            "memory_percent": vm.percent,
            "memory_used_mb": round(vm.used / (1024 * 1024)),
            "memory_total_mb": round(vm.total / (1024 * 1024)),
            "disk_percent": disk.percent,
            "resource_data_available": True,
        }
    except Exception:
        resource_data = {"resource_data_available": False}

    with total_requests_lock:
        total_reqs = total_requests_seen

    return {
        **resource_data,
        "uptime_seconds": round(time.time() - BACKEND_START_TIME),
        "total_requests_processed": total_reqs,
        "components": {
            "traffic_middleware": "running",
            "detection_engine": "running" if engine.model is not None else "warming_up",
            "incident_manager": "running",
            "mitigation_engine": "running",
            "dashboard_api": "running",
        },
        "monitoring_scope": "Application-layer HTTP traffic (no raw packet capture on hosted PaaS)",
    }


# ---------------------------------------------------------------------------
# Static dashboard (SPA shell - see static/index.html, static/js/*)
# ---------------------------------------------------------------------------
@app.get("/dashboard")
async def dashboard_page():
    return FileResponse(str(STATIC_DIR / "index.html"))


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
