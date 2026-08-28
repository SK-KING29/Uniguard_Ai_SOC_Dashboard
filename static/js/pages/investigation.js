/* ==========================================================================
   UniGuard AI - Investigation page (05)
   The judge-facing centerpiece: MITIGATE ATTACK here calls the REAL
   /api/mitigate endpoint in live mode. In demo mode it drives the
   simulation engine instead. Never ambiguous about which happened.
   ========================================================================== */

UGPages.investigation = (() => {
  let pendingAction = "block_source";

  function onShow() {
    document.querySelectorAll("#page-investigation .tab-btn").forEach(b => {
      b.onclick = () => {
        document.querySelectorAll("#page-investigation .tab-btn").forEach(x => x.classList.toggle("active", x === b));
        document.querySelectorAll("#page-investigation .tab-pane").forEach(p => p.classList.toggle("active", p.id === "inv-tab-" + b.dataset.tab));
      };
    });
    document.querySelectorAll("#page-investigation .action-select button").forEach(b => {
      b.onclick = () => { pendingAction = b.dataset.action; document.getElementById("invActionLabel").textContent = b.dataset.action; };
    });
    document.getElementById("invMitigateBtn").onclick = () => {
      document.getElementById("invModalActionLabel").textContent = pendingAction;
      document.getElementById("invModal").classList.add("show");
    };
    document.getElementById("invModalCancel").onclick = () => document.getElementById("invModal").classList.remove("show");
    document.getElementById("invModalConfirm").onclick = confirmMitigate;
  }

  function currentIncident(snap) {
    if (window.UGState.selectedIncidentId === (window.UGPhone && UGPhone.INCIDENT_ID)) {
      const phoneInc = UGPhone.getIncident();
      if (phoneInc) return phoneInc;
    }
    if (window.UGState.selectedIncidentId) {
      const found = (snap.incidents || []).find(i => i.id === window.UGState.selectedIncidentId);
      if (found) return found;
    }
    // If the phone device is actively flagged and nothing else is
    // explicitly selected, surface it - it's the most important thing.
    if (window.UGPhone && UGPhone.isActive && !window.UGState.selectedIncidentId) {
      return UGPhone.getIncident();
    }
    return snap.active_incident || (snap.incidents && snap.incidents[0]) || null;
  }

  async function confirmMitigate() {
    document.getElementById("invModal").classList.remove("show");
    const isLive = window.UGState.mode === "live";
    document.getElementById("invMitigateStatus").textContent = "Applying...";

    const isPhoneIncident = window.UGState.selectedIncidentId === (window.UGPhone && UGPhone.INCIDENT_ID)
      || (window.UGPhone && UGPhone.isActive && !window.UGState.selectedIncidentId);

    if (isPhoneIncident && window.UGPhone) {
      UGPhone.mitigate();
      document.getElementById("invMitigateStatus").textContent = `🛡️ SIMULATED mitigation applied to THIS DEVICE: ${pendingAction}`;
      return;
    }

    if (isLive) {
      const res = await UGApi.mitigate(pendingAction, "auto", window.UGState.settings?.mitigationTtl || 120,
        { limit: window.UGState.settings?.mitigationLimit });
      document.getElementById("invMitigateStatus").textContent = res.ok
        ? `🛡️ REAL mitigation applied: ${res.action}${res.target ? " → " + res.target : ""}`
        : "Error: " + (res.error || "unknown");
    } else {
      UGDemo.applyMitigation(pendingAction);
      document.getElementById("invMitigateStatus").textContent = `🛡️ SIMULATED mitigation applied: ${pendingAction}`;
    }
  }

  function fmtDur(s) { if (s == null) return "-"; return Math.round(s) + "s"; }

  function render(state) {
    const snap = state.lastSnapshot;
    if (!snap) return;
    const inc = currentIncident(snap);
    const isLive = state.mode === "live";

    document.getElementById("invSourceTag").innerHTML =
      `<span class="src-badge src-${(inc && (inc.is_phone_device || !isLive)) ? "SIMULATED" : "REAL"}">${(inc && (inc.is_phone_device || !isLive)) ? "🟣 SIMULATED" : "🟢 REAL"}</span>`;

    if (!inc) {
      document.getElementById("invBody").classList.add("page-hidden");
      document.getElementById("invEmpty").classList.remove("page-hidden");
      return;
    }
    document.getElementById("invBody").classList.remove("page-hidden");
    document.getElementById("invEmpty").classList.add("page-hidden");

    document.getElementById("invId").textContent = "INCIDENT #" + inc.id;
    document.getElementById("invType").innerHTML = `${inc.threat_type || "DoS-like Behavior"} &nbsp; <span class="badge b-${inc.severity}">${inc.severity}</span>`;

    document.getElementById("invKv").innerHTML = `
      <div><span>Device</span><span>${inc.is_phone_device ? "📱 " + inc.device : "-"}</span></div>
      <div><span>Source IP</span><span>${inc.source_ip || "-"}</span></div>
      <div><span>Target</span><span>${inc.affected_endpoint || inc.target_service || "-"}</span></div>
      <div><span>First Seen</span><span>${new Date(inc.first_detected * 1000).toLocaleTimeString()}</span></div>
      <div><span>Last Seen</span><span>${new Date(inc.last_detected * 1000).toLocaleTimeString()}</span></div>
      <div><span>Duration</span><span>${fmtDur(inc.last_detected - inc.first_detected)}</span></div>
      <div><span>Risk Score</span><span>${inc.threat_score}/100</span></div>
      <div><span>Status</span><span class="badge b-${inc.status}">${inc.status}</span></div>
      <div><span>Mitigation</span><span>${inc.mitigation_applied || "none yet"}</span></div>
    `;

    document.getElementById("invEvidence").innerHTML = (inc.evidence || []).map(e => `<li>${e}</li>`).join("") || "<li>No evidence recorded</li>";
    document.getElementById("invEvidence2").innerHTML = document.getElementById("invEvidence").innerHTML;

    const timelineHtml = inc.is_phone_device
      ? (inc.mitigation_history || []).slice().reverse().map(a =>
          `<div class="timeline-item"><span class="d d-action"></span><span>${new Date(a.time * 1000).toLocaleTimeString()} — Mitigation applied: ${a.action} (simulated)</span></div>`
        ).join("") || '<div class="timeline-item"><span class="d d-critical"></span><span>' + new Date(inc.first_detected * 1000).toLocaleTimeString() + ' — 🚨 THIS DEVICE flagged (simulated)</span></div>'
      : (snap.timeline || []).slice().reverse().slice(0, 15).map(ev =>
          `<div class="timeline-item"><span class="d d-${ev.kind}"></span><span>${new Date(ev.time * 1000).toLocaleTimeString()} — ${ev.label}</span></div>`
        ).join("");
    document.getElementById("invTimeline").innerHTML = timelineHtml || '<div class="empty-state">No events yet</div>';

    const c = snap.current || {};
    if (inc.is_phone_device) {
      document.getElementById("invTraffic").innerHTML = `
        <div class="kv">
          <div><span>Current rate</span><span>${inc.traffic_rate} req/s</span></div>
          <div><span>Connection rate</span><span>${inc.connection_rate} conn/s</span></div>
          <div><span>Baseline</span><span>~15 req/s</span></div>
          <div><span>Status</span><span class="badge b-${inc.status}">${inc.status}</span></div>
        </div>`;
      document.getElementById("invImpact").innerHTML = `
        <div class="kv">
          <div><span>Target service</span><span>${inc.target_service}</span></div>
          <div><span>Total requests (est.)</span><span>${Math.round(inc.traffic_rate * 60)}</span></div>
          <div><span>Impact level</span><span class="badge b-${inc.severity}">${inc.severity}</span></div>
        </div>`;
      document.getElementById("invResponse").innerHTML = (inc.mitigation_history && inc.mitigation_history.length)
        ? inc.mitigation_history.slice().reverse().map(a => `<div style="margin-bottom:6px;font-size:12px;">${new Date(a.time * 1000).toLocaleTimeString()} — <b>${a.action}</b> → ${a.target} (simulated)</div>`).join("")
        : '<div class="empty-state">No response actions taken yet</div>';
    } else {
      document.getElementById("invTraffic").innerHTML = `
        <div class="kv">
          <div><span>Current rate</span><span>${(c.req_per_sec ?? 0).toFixed(1)} req/s</span></div>
          <div><span>Peak rate</span><span>${(inc.peak_rate ?? 0).toFixed ? inc.peak_rate.toFixed(1) : inc.peak_rate} req/s</span></div>
          <div><span>Baseline</span><span>${inc.baseline_rate} req/s</span></div>
          <div><span>Allowed (post-mitigation)</span><span>${(c.allowed_per_sec ?? 0).toFixed(1)} req/s</span></div>
        </div>`;
      document.getElementById("invImpact").innerHTML = `
        <div class="kv">
          <div><span>Target service</span><span>${inc.affected_endpoint || "-"}</span></div>
          <div><span>Total requests (window)</span><span>${Math.round((c.req_per_sec ?? 0) * 60)}</span></div>
          <div><span>Total bytes (window)</span><span>${Math.round((c.bytes_per_sec ?? 0) * 60)}</span></div>
          <div><span>Impact level</span><span class="badge b-${inc.severity}">${inc.severity}</span></div>
        </div>`;
      const audit = (snap.audit_log || []).slice().reverse();
      document.getElementById("invResponse").innerHTML = audit.length
        ? audit.map(a => `<div style="margin-bottom:6px;font-size:12px;">${new Date(a.time * 1000).toLocaleTimeString()} — <b>${a.action}</b>${a.target ? " → " + a.target : ""}</div>`).join("")
        : '<div class="empty-state">No response actions taken yet</div>';
    }

    document.getElementById("invMitigateBtn").disabled = inc.status === "RESOLVED";
  }

  return { onShow, render };
})();
