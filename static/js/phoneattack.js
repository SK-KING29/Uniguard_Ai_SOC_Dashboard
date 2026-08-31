/* ==========================================================================
   UniGuard AI - "This Device" phone-triggered simulation (backend-relayed)

   Deliberately SEPARATE from UGDemo (the background network engine).
   UGDemo keeps producing normal busy background traffic no matter what
   happens here. This module only ever represents ONE synthetic device -
   "THIS DEVICE" - so pages can highlight exactly one thing when the
   mobile demo is started.

   This talks to the small relay in app.py (/api/mobile-demo/*) so a START
   pressed on a phone shows up on a laptop SOC dashboard even when they're
   on different networks - the backend is the shared source of truth, not
   local browser state. The traffic/risk NUMBERS are still a SAFE, PURELY
   SIMULATED ramp computed server-side from elapsed time; nothing here (or
   in app.py's relay) ever sends a real request to a target endpoint.
   ========================================================================== */

const UGPhone = (() => {
  const INCIDENT_ID = "PHONE-DEVICE";
  const DEVICE_LABEL = "THIS DEVICE";
  const THREAT_TYPE = "DOS-LIKE / HTTP FLOOD";

  let cached = null;       // last-known incident snapshot from the backend
  let lastPhase = "idle";  // used to detect phase transitions -> events
  let listeners = [];
  let polling = false;

  function on(eventName, cb) {
    listeners.push({ eventName, cb });
  }
  function emit(eventName, payload) {
    listeners.filter(l => l.eventName === eventName).forEach(l => { try { l.cb(payload); } catch (e) { console.error(e); } });
  }

  // Safe in non-browser contexts too (e.g. the node-based demo-engine
  // test harness, which has no `window`/`fetch`).
  function hasFetch() { return typeof fetch === "function"; }

  function applySnapshot(inc) {
    const prevPhase = lastPhase;
    if (!inc) {
      cached = null;
      lastPhase = "idle";
      if (prevPhase !== "idle") emit("cleared", null);
      return;
    }
    cached = inc;
    lastPhase = inc.phase || lastPhase;
    if (prevPhase === "idle" && inc.phase === "active") emit("incident_start", inc);
    if (prevPhase !== "mitigating" && inc.phase === "mitigating") emit("mitigated", inc);
    if (prevPhase !== "resolved" && inc.phase === "resolved") emit("recovered", inc);
  }

  async function postJSON(url, body) {
    if (!hasFetch()) return null;
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {}),
      });
      return await res.json();
    } catch (e) {
      console.error("UGPhone relay request failed:", e);
      return null;
    }
  }

  function start(intensity) {
    if (!["LOW", "MEDIUM", "HIGH"].includes(intensity)) intensity = "MEDIUM";
    postJSON("/api/mobile-demo/start", { intensity }).then((res) => {
      if (res && res.incident) applySnapshot(res.incident);
    });
  }

  function stop() {
    if (hasFetch()) fetch("/api/mobile-demo/stop", { method: "POST" }).catch(() => {});
    // Hard stop from the STOP button - clears immediately on this device,
    // regardless of relay latency.
    cached = null;
    lastPhase = "idle";
    emit("cleared", null);
  }

  function mitigate() {
    if (!cached || cached.status !== "INVESTIGATING") return;
    postJSON("/api/mobile-demo/mitigate", {}).then((res) => {
      if (res && res.incident) applySnapshot(res.incident);
    });
  }

  async function poll() {
    if (!hasFetch() || polling) return;
    polling = true;
    try {
      const res = await fetch("/api/mobile-demo/state", { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        applySnapshot(data.incident);
      }
    } catch (e) {
      // Connection hiccup - keep last-known state, the next tick retries.
    } finally {
      polling = false;
    }
  }

  // Called once per second by the app's central tick loop, in every mode -
  // this is what makes a phone-triggered incident show up on any other
  // device polling the same backend.
  function tick() {
    poll();
  }

  function getIncident() {
    return cached;
  }

  return {
    start, stop, mitigate, tick, on, getIncident,
    get phase() { return cached ? cached.phase : "idle"; },
    get isActive() { return !!cached && (cached.phase === "active" || cached.phase === "mitigating"); },
    get isVisible() { return !!cached; },
    get intensity() { return cached ? cached.intensity : "MEDIUM"; },
    DEVICE_LABEL, THREAT_TYPE, INCIDENT_ID,
  };
})();
if (typeof window !== "undefined") window.UGPhone = UGPhone;
