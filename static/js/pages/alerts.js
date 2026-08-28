/* ==========================================================================
   UniGuard AI - Alerts page (04)
   ========================================================================== */

UGPages.alerts = (() => {
  function onShow() {}

  function render(state) {
    const snap = state.lastSnapshot;
    if (!snap) return;
    const isLive = state.mode === "live";
    const incidents = snap.incidents || [];
    const active = incidents.filter(i => i.status !== "RESOLVED");
    const resolved = incidents.filter(i => i.status === "RESOLVED");

    function row(i) {
      const ackDisabled = isLive ? 'disabled title="Not a backend capability in live mode - use Investigation → Mitigate for real response"' : "";
      const resolveDisabled = isLive ? 'disabled title="Recovery is automatic based on real traffic - not manually resolvable"' : "";
      return `
        <tr>
          <td><span class="badge b-${i.severity}">${i.severity}</span></td>
          <td>DoS-like</td>
          <td>${new Date(i.first_detected * 1000).toLocaleTimeString()}</td>
          <td>${i.source_ip || "-"}</td>
          <td>${i.affected_endpoint || "-"}</td>
          <td><span class="badge b-${i.status}">${i.status}</span></td>
          <td>
            <div class="btn-row">
              <button class="btn small" onclick="UGThreatsOpen('${i.id}')">Investigate</button>
              <button class="btn small" ${ackDisabled}>Acknowledge</button>
              <button class="btn small" ${resolveDisabled}>Resolve</button>
            </div>
          </td>
        </tr>`;
    }

    const phoneInc = window.UGPhone ? UGPhone.getIncident() : null;
    function phoneRow() {
      if (!phoneInc) return "";
      return `
        <tr class="row-phone-highlight">
          <td><span class="badge b-${phoneInc.severity}">${phoneInc.severity}</span></td>
          <td>${phoneInc.threat_type}</td>
          <td>${new Date(phoneInc.first_detected * 1000).toLocaleTimeString()}</td>
          <td>📱 ${phoneInc.device}</td>
          <td>${phoneInc.target_service}</td>
          <td><span class="badge b-${phoneInc.status}">${phoneInc.status}</span></td>
          <td><div class="btn-row"><button class="btn small" onclick="UGThreatsOpen('${phoneInc.id}')">Investigate</button></div></td>
        </tr>`;
    }

    document.getElementById("alertsActiveBody").innerHTML = (phoneInc && phoneInc.status !== "RESOLVED" ? phoneRow() : "") + (active.length
      ? active.map(row).join("") : ((phoneInc && phoneInc.status !== "RESOLVED") ? "" : '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:16px;">No active alerts</td></tr>'));
    document.getElementById("alertsResolvedBody").innerHTML = (phoneInc && phoneInc.status === "RESOLVED" ? phoneRow() : "") + (resolved.length
      ? resolved.map(row).join("") : ((phoneInc && phoneInc.status === "RESOLVED") ? "" : '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:16px;">No resolved alerts yet</td></tr>'));

    document.getElementById("alertsNotice").textContent = isLive
      ? "Live mode: Acknowledge/Resolve are disabled - the backend has no manual-acknowledge concept, and recovery is automatic based on real traffic returning to baseline. Use Investigate → Mitigate Attack for real response actions."
      : "Demo mode: showing simulated alerts.";
  }

  return { onShow, render };
})();
