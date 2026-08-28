/* ==========================================================================
   UniGuard AI - Network Graph page (07)
   ========================================================================== */

UGPages.network = (() => {
  let scale = 1;
  let lastNodes = [];

  function onShow() {
    document.getElementById("netZoomIn").onclick = () => setScale(scale + 0.15);
    document.getElementById("netZoomOut").onclick = () => setScale(scale - 0.15);
    document.getElementById("netZoomReset").onclick = () => setScale(1);
  }

  function setScale(s) {
    scale = Math.max(0.5, Math.min(2, s));
    document.getElementById("netSvg").style.transform = `scale(${scale})`;
  }

  function riskColor(risk) {
    return risk === "CRITICAL" ? "#d6484a" : risk === "HIGH" ? "#e0913c" : risk === "MEDIUM" ? "#d6b83c" : "#3cb371";
  }

  function buildLiveNodes(snap) {
    const c = snap.current || {};
    const sources = Object.keys(c.per_endpoint || {}).length ? [c.top_ip].filter(Boolean) : [];
    const active = snap.active_incident;
    const nodes = (sources.length ? sources : (active ? [active.source_ip] : [])).filter(Boolean);
    return nodes.map(ip => ({ ip, risk: active && active.source_ip === ip ? active.severity : "LOW" }));
  }

  function buildDemoNodes() {
    return [
      { ip: "192.168.1.25", risk: "CRITICAL" },
      { ip: "192.168.1.66", risk: "HIGH" },
      { ip: "192.168.1.50", risk: "MEDIUM" },
      { ip: "192.168.1.51", risk: "LOW" },
      { ip: "192.168.1.52", risk: "LOW" },
      { ip: "8.8.8.8", risk: "LOW", external: true },
    ];
  }

  function drawGraph(nodes, targetLabel) {
    lastNodes = nodes;
    const svg = document.getElementById("netSvg");
    const cx = 350, cy = 210, radius = 150;
    let html = `<circle cx="${cx}" cy="${cy}" r="26" fill="#161b26" stroke="#3ba7d1" stroke-width="2"/>
      <text x="${cx}" y="${cy - 32}" text-anchor="middle" fill="#e6e9ef" font-size="11">${targetLabel}</text>
      <text x="${cx}" y="${cy + 4}" text-anchor="middle" fill="#3ba7d1" font-size="9">TARGET</text>`;

    nodes.forEach((n, i) => {
      const angle = (2 * Math.PI * i) / Math.max(1, nodes.length) - Math.PI / 2;
      const x = cx + radius * Math.cos(angle);
      const y = cy + radius * Math.sin(angle);
      const color = riskColor(n.risk);
      html += `<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" stroke="${color}" stroke-width="1.5" opacity="0.6"/>
        <circle cx="${x}" cy="${y}" r="16" fill="#161b26" stroke="${color}" stroke-width="2"
          style="cursor:pointer" onclick="UGNetworkSelect(${i})"/>
        <text x="${x}" y="${y - 22}" text-anchor="middle" fill="${color}" font-size="9">${n.ip}</text>`;
    });

    // Phone device path, drawn prominently on top: device -> UniGuard -> target.
    const phoneInc = window.UGPhone ? UGPhone.getIncident() : null;
    if (phoneInc && phoneInc.status !== "RESOLVED") {
      const px = 90, py = 60;
      const gx = cx, gy = cy - radius - 55 > 20 ? cy - radius - 55 : 40;
      const color = "#d6484a";
      html += `
        <line x1="${px}" y1="${py}" x2="${gx}" y2="${gy}" stroke="${color}" stroke-width="2.5" stroke-dasharray="5,3">
          <animate attributeName="stroke-dashoffset" from="16" to="0" dur="0.6s" repeatCount="indefinite"/>
        </line>
        <line x1="${gx}" y1="${gy}" x2="${cx}" y2="${cy}" stroke="${color}" stroke-width="2.5" stroke-dasharray="5,3">
          <animate attributeName="stroke-dashoffset" from="16" to="0" dur="0.6s" repeatCount="indefinite"/>
        </line>
        <circle cx="${px}" cy="${py}" r="18" fill="#1a1015" stroke="${color}" stroke-width="2.5"
          style="cursor:pointer" onclick="UGNetworkSelectPhone()"/>
        <text x="${px}" y="${py + 4}" text-anchor="middle" font-size="14">📱</text>
        <text x="${px}" y="${py - 26}" text-anchor="middle" fill="${color}" font-size="10" font-weight="700">THIS DEVICE</text>
        <circle cx="${gx}" cy="${gy}" r="16" fill="#161b26" stroke="${color}" stroke-width="2"/>
        <text x="${gx}" y="${gy + 4}" text-anchor="middle" font-size="13">🛡️</text>
      `;
    }

    svg.innerHTML = html;
  }

  window.UGNetworkSelectPhone = () => {
    const inc = window.UGPhone ? UGPhone.getIncident() : null;
    if (!inc) return;
    document.getElementById("netNodeInfo").innerHTML = `
      <div class="kv">
        <div><span>Device</span><span>📱 ${inc.device}</span></div>
        <div><span>Source</span><span>${inc.source_ip}</span></div>
        <div><span>Risk</span><span class="badge b-${inc.severity}">${inc.severity}</span></div>
        <div><span>Status</span><span>Under investigation (simulated)</span></div>
      </div>`;
  };

  window.UGNetworkSelect = (i) => {
    const n = lastNodes[i];
    if (!n) return;
    document.getElementById("netNodeInfo").innerHTML = `
      <div class="kv">
        <div><span>IP</span><span>${n.ip}</span></div>
        <div><span>Risk</span><span class="badge b-${n.risk}">${n.risk}</span></div>
        <div><span>Type</span><span>${n.external ? "External" : "Internal source"}</span></div>
        <div><span>Status</span><span>${n.risk === "CRITICAL" || n.risk === "HIGH" ? "Under investigation" : "Monitored"}</span></div>
      </div>`;
  };

  function render(state) {
    const snap = state.lastSnapshot;
    if (!snap) return;
    const isLive = state.mode === "live";
    document.getElementById("netModeNotice").textContent = isLive
      ? "Live mode - nodes reflect real observed source IP(s) from current traffic"
      : "Demo mode - example topology per the reference design";

    const nodes = isLive ? buildLiveNodes(snap) : buildDemoNodes();
    drawGraph(nodes, isLive ? "This server" : "192.168.1.100");

    if (!nodes.length) {
      document.getElementById("netNodeInfo").innerHTML = '<div class="empty-state">No source traffic observed yet - click a node once traffic appears</div>';
    }
  }

  return { onShow, render };
})();
