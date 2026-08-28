/* ==========================================================================
   UniGuard AI - Demo/Simulation engine (client-side only)

   Produces synthetic data shaped IDENTICALLY to the real /api/metrics
   response, so page renderers can consume either source through the same
   code. Nothing here ever touches the real backend - this is pure
   client-side simulation, clearly tagged SIMULATED everywhere it surfaces.

   Values move smoothly toward per-scenario targets (lerp + small sine
   jitter) rather than jumping randomly each tick, per the design spec.
   ========================================================================== */

const UGDemo = (() => {
  const DEMO_SOURCE_IPS = ["192.168.1.25", "192.168.1.50", "192.168.1.51", "192.168.1.52", "192.168.1.66", "192.168.1.73", "192.168.1.84", "10.0.0.8", "10.0.0.15", "10.0.0.22", "172.16.5.10", "172.16.5.19"];
  const DEMO_TARGET_IP = "192.168.1.100";
  // Multiple destination devices so the background network reads as a
  // genuinely busy SOC (web/api/db/auth tiers), not one lonely target.
  const DEMO_TARGET_DEVICES = [
    { ip: "192.168.1.100", label: "Web Server" },
    { ip: "192.168.1.101", label: "API Gateway" },
    { ip: "192.168.1.102", label: "Auth Service" },
    { ip: "192.168.1.103", label: "Database" },
  ];
  const ENDPOINTS = ["/", "/api/login", "/api/data", "/api/search"];
  const PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS"];

  // Bumped up so DEMO MODE opens visibly active rather than sparse -
  // this is purely cosmetic simulated volume, never sent anywhere.
  const SCENARIO_PROFILES = {
    normal:     { reqTarget: 4200, riskTarget: 14, burst: 0.08, concentration: 0.25 },
    suspicious: { reqTarget: 6800, riskTarget: 48, burst: 0.35, concentration: 0.55 },
    dos:        { reqTarget: 11000, riskTarget: 94, burst: 0.75, concentration: 0.9 },
    mitigation: { reqTarget: 3600, riskTarget: 30, burst: 0.1,  concentration: 0.3 },
    recovery:   { reqTarget: 4000, riskTarget: 10, burst: 0.05, concentration: 0.2 },
  };

  let state = null;

  function freshState() {
    return {
      running: false,
      scenario: "normal",
      speed: 1,
      t: 0,
      reqPerSec: 4200,
      baselineRate: 4200,
      riskScore: 10,
      systemStatus: "PROTECTED",
      history: [],
      timeline: [{ time: Date.now() / 1000, label: "Demo baseline established (simulated)", kind: "info" }],
      incidents: [],
      activeIncidentId: null,
      auditLog: [],
      alertStreak: 0,
      uptimeStart: Date.now() / 1000,
      blipTimer: 0,
      blipMagnitude: 0,
    };
  }

  // Safe in non-browser contexts too (e.g. the node-based demo-engine test
  // harness, which has no `window`) - the phone module is always optional.
  function getPhoneIncident() {
    try {
      if (typeof window !== "undefined" && window.UGPhone) return window.UGPhone.getIncident();
    } catch (e) { /* ignore */ }
    return null;
  }

  function reset() {
    state = freshState();
  }
  reset();

  function log(label, kind) {
    state.timeline.push({ time: Date.now() / 1000, label, kind });
    if (state.timeline.length > 100) state.timeline.shift();
  }

  function setScenario(name) {
    if (!SCENARIO_PROFILES[name]) return;
    state.scenario = name;
    log("Demo scenario changed to " + name.toUpperCase() + " (simulated)", "action");
  }

  function start() { state.running = true; }
  function pause() { state.running = false; }
  function setSpeed(v) { state.speed = v; }

  function applyMitigation(action) {
    state.scenario = "mitigation";
    const inc = state.incidents.find((i) => i.id === state.activeIncidentId);
    if (inc) {
      inc.status = "MITIGATING";
      inc.mitigation_applied = action;
      inc.mitigation_applied_at = Date.now() / 1000;
    }
    state.auditLog.push({ time: Date.now() / 1000, action, target: DEMO_SOURCE_IPS[0] });
    log("Demo mitigation applied: " + action + " (simulated)", "action");
  }

  function lerp(a, b, f) { return a + (b - a) * f; }

  function tick(dtSeconds) {
    if (!state.running) return;
    const dt = dtSeconds * state.speed;
    state.t += dt;

    const profile = SCENARIO_PROFILES[state.scenario];

    // Natural background fluctuation: a few sine components at different
    // periods plus light random jitter, so traffic reads as alive (small
    // peaks and dips) instead of an almost-flat line.
    let reqWobble =
      Math.sin(state.t * 0.35) * 0.05 +
      Math.sin(state.t * 1.3 + 1.7) * 0.025 +
      Math.sin(state.t * 3.1 + 0.4) * 0.012 +
      (Math.random() - 0.5) * 0.03;

    // Occasional small organic peak/dip, layered on top of the smooth wobble.
    if (state.blipTimer > 0) {
      state.blipTimer -= dt;
      reqWobble += state.blipMagnitude;
    } else if (Math.random() < 0.02 * dt) {
      state.blipMagnitude = (Math.random() < 0.5 ? -1 : 1) * (0.08 + Math.random() * 0.14);
      state.blipTimer = 1.5 + Math.random() * 2.5;
    }

    // Risk keeps the original, smaller wobble - kept separate from the
    // richer traffic wobble so background fluctuation can never accidentally
    // cross a severity threshold on its own.
    const riskWobble = Math.sin(state.t * 0.6) * 0.03 + (Math.random() - 0.5) * 0.02;

    // A phone-triggered "This Device" incident overlays a clear, controlled
    // spike on top of the background traffic - ramping in as the phone
    // incident ramps in, and smoothly decaying back to baseline as it's
    // mitigated, driven entirely by the already-decaying traffic_rate the
    // backend relay reports (see phoneattack.js / /api/mobile-demo/state).
    const phoneInc = getPhoneIncident();
    let phoneSpike = 0;
    if (phoneInc && phoneInc.status !== "RESOLVED") {
      const ceiling = { LOW: 140, MEDIUM: 420, HIGH: 820 }[phoneInc.intensity] || 420;
      phoneSpike = Math.min(1.6, (phoneInc.traffic_rate || 0) / ceiling) * 0.9;
    }

    const backgroundTarget = profile.reqTarget * (1 + reqWobble);
    const targetReq = backgroundTarget * (1 + phoneSpike);
    const targetRisk = profile.riskTarget * (1 + riskWobble * 0.5);

    state.reqPerSec = lerp(state.reqPerSec, targetReq, Math.min(1, 0.12 * state.speed));
    state.riskScore = lerp(state.riskScore, targetRisk, Math.min(1, 0.15 * state.speed));
    if (state.scenario === "normal" || state.scenario === "recovery") {
      // Track the background level only (never the phone spike) so the
      // baseline line stays a true "normal" reference during and after
      // a phone-triggered spike, and traffic visibly returns to it.
      state.baselineRate = lerp(state.baselineRate, backgroundTarget, 0.05);
    }

    const severity = state.riskScore >= 75 ? "CRITICAL" : state.riskScore >= 50 ? "HIGH" : state.riskScore >= 25 ? "MEDIUM" : "LOW";
    const status = state.riskScore >= 50 ? "ATTACK" : state.riskScore >= 25 ? "SUSPICIOUS" : "NORMAL";

    // incident lifecycle mirrors the real IncidentManager's debounce/recovery
    // pattern, adapted for scenario-driven demo data
    if (status !== "NORMAL") {
      state.alertStreak++;
      if (!state.activeIncidentId && state.alertStreak >= 2) {
        const id = "DEMO-" + Math.random().toString(16).slice(2, 8).toUpperCase();
        state.activeIncidentId = id;
        const sourceIp = DEMO_SOURCE_IPS[Math.floor(Math.random() * 3)];
        state.incidents.unshift({
          id, first_detected: Date.now() / 1000, last_detected: Date.now() / 1000,
          status: "ACTIVE", affected_endpoint: ENDPOINTS[Math.floor(Math.random() * ENDPOINTS.length)],
          source_ip: sourceIp, peak_rate: state.reqPerSec, baseline_rate: state.baselineRate,
          threat_score: Math.round(state.riskScore), severity,
          evidence: buildEvidence(profile, state.riskScore, state.baselineRate, state.reqPerSec),
          mitigation_applied: null, mitigation_applied_at: null, source: "SIMULATED",
        });
        log((status === "ATTACK" ? "🚨 SIMULATED DoS-like behavior detected" : "Simulated anomaly detected") + " - demo incident opened", status === "ATTACK" ? "critical" : "warning");
      } else if (state.activeIncidentId) {
        const inc = state.incidents.find((i) => i.id === state.activeIncidentId);
        if (inc) {
          inc.last_detected = Date.now() / 1000;
          inc.peak_rate = Math.max(inc.peak_rate, state.reqPerSec);
          inc.threat_score = Math.round(state.riskScore);
          inc.severity = severity;
          inc.evidence = buildEvidence(profile, state.riskScore, state.baselineRate, state.reqPerSec);
        }
      }
      state.systemStatus = status;
    } else {
      state.alertStreak = 0;
      if (state.activeIncidentId) {
        const inc = state.incidents.find((i) => i.id === state.activeIncidentId);
        if (inc && state.reqPerSec < state.baselineRate * 1.5) {
          inc.status = "RESOLVED";
          inc.resolved_at = Date.now() / 1000;
          state.activeIncidentId = null;
          log("🟢 Simulated recovery - traffic normalized (demo)", "success");
        }
      }
      state.systemStatus = "PROTECTED";
    }

    const window = buildWindow(state, profile, status, severity);
    state.history.push(window);
    if (state.history.length > 120) state.history.shift();
  }

  function buildEvidence(profile, riskScore, baselineRate, reqPerSec) {
    const ev = [];
    const dev = baselineRate > 0 ? ((reqPerSec - baselineRate) / baselineRate) * 100 : 0;
    if (dev > 50) ev.push(`[SIMULATED] Request rate ${dev.toFixed(0)}% above baseline (${reqPerSec.toFixed(0)} req/s vs ${baselineRate.toFixed(0)} req/s baseline)`);
    if (profile.burst > 0.4) ev.push("[SIMULATED] Sudden traffic burst pattern detected");
    if (profile.concentration > 0.5) ev.push("[SIMULATED] Traffic concentrated on a small number of endpoints");
    if (riskScore > 70) ev.push("[SIMULATED] Sustained high-volume traffic from limited source IPs (DoS-like pattern)");
    if (!ev.length) ev.push("[SIMULATED] Traffic within expected range");
    return ev;
  }

  function buildWindow(s, profile, status, severity) {
    const perEndpoint = {};
    const dominant = ENDPOINTS[0];
    let remaining = s.reqPerSec;
    ENDPOINTS.forEach((ep, i) => {
      const share = ep === dominant ? profile.concentration : (1 - profile.concentration) / (ENDPOINTS.length - 1);
      perEndpoint[ep] = Math.round(s.reqPerSec * share);
    });
    return {
      t: Date.now() / 1000,
      req_per_sec: Math.round(s.reqPerSec * 10) / 10,
      allowed_per_sec: s.activeIncidentId && s.incidents.find(i => i.id === s.activeIncidentId)?.mitigation_applied
        ? Math.round(s.reqPerSec * 0.15 * 10) / 10
        : Math.round(s.reqPerSec * 10) / 10,
      bytes_per_sec: Math.round(s.reqPerSec * 42),
      unique_ips: Math.max(1, Math.round(3 + profile.concentration * 5)),
      endpoint_concentration: profile.concentration,
      burst_indicator: profile.burst,
      mitigated_count: 0,
      per_endpoint: perEndpoint,
      top_ip: DEMO_SOURCE_IPS[0],
      anomaly_score: Math.round(Math.min(100, s.riskScore * 1.05)),
      model_ready: true,
      baseline_deviation_pct: s.baselineRate > 0 ? Math.round(((s.reqPerSec - s.baselineRate) / s.baselineRate) * 1000) / 10 : 0,
      baseline_rate: Math.round(s.baselineRate * 10) / 10,
      risk_score: Math.round(s.riskScore * 10) / 10,
      severity, status,
      components: {
        rate_anomaly: Math.round(Math.min(100, (s.riskScore / 100) * 110)),
        baseline_deviation: Math.round(Math.min(100, s.riskScore)),
        traffic_burst: Math.round(profile.burst * 100),
        endpoint_concentration: Math.round(profile.concentration * 100),
      },
      evidence: buildEvidence(profile, s.riskScore, s.baselineRate, s.reqPerSec),
    };
  }

  function getSnapshot() {
    const current = state.history[state.history.length - 1] || buildWindow(state, SCENARIO_PROFILES.normal, "NORMAL", "LOW");
    const active = state.activeIncidentId ? state.incidents.find((i) => i.id === state.activeIncidentId) : null;
    return {
      system_status: state.systemStatus,
      current,
      history: state.history.slice(-120),
      active_incident: active || null,
      incidents: state.incidents.slice(0, 20),
      timeline: state.timeline.slice(-30),
      mitigation: { blocked: [], rate_limited: [], protected_endpoints: [] },
      audit_log: state.auditLog.slice(-30),
      uptime_seconds: Math.round(Date.now() / 1000 - state.uptimeStart),
      monitoring_scope: "SIMULATED_DEMO_DATA",
      update_mode: "client-side simulation",
      active_connections: Math.max(0, Math.round(current.unique_ips * 1.5)),
      total_requests: Math.round(state.history.reduce((a, w) => a + w.req_per_sec, 0)),
      ip_intelligence: active ? {
        ip: active.source_ip, request_count: Math.round(active.peak_rate * 5), unique_user_agents: 1,
        dominant_user_agent: "UniGuard-Demo-Simulator/1.0", timing_regularity: 0.9,
        endpoint_spread: 1, authenticity_note: "[SIMULATED] Highly regular request timing consistent with scripted traffic",
        concern_level: "ELEVATED", source: "SIMULATED",
      } : null,
      source: "SIMULATED",
    };
  }

  return {
    reset, start, pause, setSpeed, setScenario, applyMitigation, tick, getSnapshot,
    get isRunning() { return state.running; },
    get scenario() { return state.scenario; },
    get speed() { return state.speed; },
    DEMO_SOURCE_IPS, DEMO_TARGET_IP, DEMO_TARGET_DEVICES, PROTOCOLS,
  };
})();
