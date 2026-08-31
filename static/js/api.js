/* ==========================================================================
   UniGuard AI - Real API layer
   Every function here calls an actual backend endpoint. Nothing in this
   file generates or fabricates data - that is demo.js's job, kept
   deliberately separate so real and simulated data can never be confused
   at the source.
   ========================================================================== */

const UGApi = (() => {
  async function getJSON(url, opts) {
    const res = await fetch(url, { cache: "no-store", ...opts });
    if (!res.ok && res.status >= 500) {
      throw new Error("Backend error " + res.status);
    }
    return res.json();
  }

  return {
    async getMetrics() {
      return getJSON("/api/metrics");
    },
    async getRecentTraffic(limit = 50) {
      return getJSON("/api/traffic/recent?limit=" + limit);
    },
    async getHealth() {
      return getJSON("/api/health");
    },
    async getSystem() {
      return getJSON("/api/system");
    },
    async getLedger(limit = 50) {
      return getJSON("/api/ledger?limit=" + limit);
    },
    async getBenchmark() {
      return getJSON("/api/benchmark");
    },
    async getSihAlignment() {
      return getJSON("/api/sih-alignment");
    },
    async ipLookup(ip) {
      return getJSON("/api/ip-lookup/" + encodeURIComponent(ip));
    },
    async mitigate(action, target, ttl, extra) {
      const res = await fetch("/api/mitigate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, target: target || "auto", ttl: ttl || 120, ...extra }),
      });
      return res.json();
    },
    async reset() {
      const res = await fetch("/api/reset", { method: "POST" });
      return res.json();
    },
  };
})();
