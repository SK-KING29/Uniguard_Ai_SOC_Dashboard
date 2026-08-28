/* ==========================================================================
   UniGuard AI - Threats page (03)
   ========================================================================== */

UGPages.threats = (() => {
  let filter = "ALL";

  function onShow() {
    document.querySelectorAll("#page-threats .severity-filter button").forEach(b => {
      b.onclick = () => {
        filter = b.dataset.sev;
        document.querySelectorAll("#page-threats .severity-filter button").forEach(x => x.classList.toggle("active", x === b));
        render(window.UGState);
      };
    });
  }

  function openInvestigation(id) {
    window.UGState.selectedIncidentId = id;
    location.hash = "#/investigation";
  }
  window.UGThreatsOpen = openInvestigation;

  function render(state) {
    const snap = state.lastSnapshot;
    if (!snap) return;
    let rows = snap.incidents || [];
    if (filter !== "ALL") rows = rows.filter(i => i.severity === filter);

    const phoneInc = window.UGPhone ? UGPhone.getIncident() : null;
    const showPhoneRow = phoneInc && phoneInc.status !== "RESOLVED" && (filter === "ALL" || filter === phoneInc.severity);
    const phoneRowHtml = showPhoneRow ? `
      <tr class="row-phone-highlight" style="cursor:pointer" onclick="UGThreatsOpen('${phoneInc.id}')">
        <td>${new Date(phoneInc.first_detected * 1000).toLocaleTimeString()}</td>
        <td>${phoneInc.threat_type}</td>
        <td>📱 ${phoneInc.device}</td>
        <td>${phoneInc.target_service}</td>
        <td>${phoneInc.threat_score}</td>
        <td><span class="badge b-${phoneInc.severity}">${phoneInc.severity}</span></td>
        <td><span class="badge b-${phoneInc.status}">${phoneInc.status}</span></td>
      </tr>` : "";

    const tbody = document.getElementById("threatsBody");
    tbody.innerHTML = phoneRowHtml + (rows.length ? rows.map(i => `
      <tr style="cursor:pointer" onclick="UGThreatsOpen('${i.id}')">
        <td>${new Date(i.first_detected * 1000).toLocaleTimeString()}</td>
        <td>DoS-like Behavior</td>
        <td>${i.source_ip || "-"}</td>
        <td>${i.affected_endpoint || "-"}</td>
        <td>${i.threat_score}</td>
        <td><span class="badge b-${i.severity}">${i.severity}</span></td>
        <td><span class="badge b-${i.status}">${i.status}</span></td>
      </tr>
    `).join("") : (phoneRowHtml ? "" : '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:20px;">No threats match this filter</td></tr>'));
  }

  return { onShow, render };
})();
