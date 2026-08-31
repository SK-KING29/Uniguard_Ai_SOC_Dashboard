// Load demo.js in node (it's a browser global IIFE with no deps beyond Math/Date, both native to node)
const fs = require('fs');
const code = fs.readFileSync('static/js/demo.js', 'utf8');
eval(code + '\nglobal.UGDemo = UGDemo;');

function assert(cond, msg) {
  if (!cond) { console.error("FAIL:", msg); process.exitCode = 1; }
  else { console.log("PASS:", msg); }
}

// Test 1: normal scenario stays calm, no incident
UGDemo.reset();
UGDemo.start();
UGDemo.setScenario('normal');
for (let i = 0; i < 60; i++) UGDemo.tick(1);
let snap = UGDemo.getSnapshot();
assert(snap.system_status === 'PROTECTED', 'normal scenario stays PROTECTED (got ' + snap.system_status + ')');
assert(snap.active_incident === null, 'no incident opens during normal traffic');
assert(snap.current.req_per_sec > 500 && snap.current.req_per_sec < 2500, 'normal req/s in realistic range (' + snap.current.req_per_sec + ')');

// Test 2: dos scenario ramps up and opens a CRITICAL incident
UGDemo.reset();
UGDemo.start();
UGDemo.setScenario('dos');
for (let i = 0; i < 30; i++) UGDemo.tick(1);
snap = UGDemo.getSnapshot();
assert(snap.system_status === 'ATTACK', 'dos scenario escalates to ATTACK (got ' + snap.system_status + ')');
assert(snap.active_incident !== null, 'incident opens during dos scenario');
assert(snap.active_incident.severity === 'CRITICAL', 'severity reaches CRITICAL (got ' + snap.active_incident.severity + ')');
assert(snap.current.req_per_sec > 5000, 'req/s ramps toward 7000 target (' + snap.current.req_per_sec + ')');
assert(Array.isArray(snap.active_incident.evidence) && snap.active_incident.evidence.length > 0, 'incident has evidence');
assert(snap.active_incident.evidence[0].includes('[SIMULATED]'), 'evidence is clearly tagged SIMULATED');

// Test 3: mitigation reduces allowed traffic and eventually resolves
UGDemo.applyMitigation('block_source');
snap = UGDemo.getSnapshot();
assert(snap.active_incident.status === 'MITIGATING', 'incident status becomes MITIGATING after applyMitigation');
assert(snap.active_incident.mitigation_applied === 'block_source', 'mitigation_applied recorded');
assert(snap.active_incident.mitigation_applied_at !== null, 'mitigation_applied_at timestamp recorded');

UGDemo.setScenario('recovery');
for (let i = 0; i < 60; i++) UGDemo.tick(1);
snap = UGDemo.getSnapshot();
assert(snap.system_status === 'PROTECTED', 'system recovers to PROTECTED (got ' + snap.system_status + ')');
assert(snap.active_incident === null, 'incident cleared after recovery');
const resolved = snap.incidents.find(i => i.status === 'RESOLVED');
assert(!!resolved, 'a resolved incident exists in history');

// Test 4: snapshot shape matches what page renderers expect (same field names as real API)
const requiredTop = ['system_status','current','history','active_incident','incidents','timeline','mitigation','audit_log','uptime_seconds','active_connections','total_requests','ip_intelligence'];
requiredTop.forEach(f => assert(f in snap, 'snapshot has top-level field: ' + f));
const requiredCurrent = ['req_per_sec','allowed_per_sec','bytes_per_sec','unique_ips','risk_score','severity','status','components','evidence','per_endpoint'];
requiredCurrent.forEach(f => assert(f in snap.current, 'current window has field: ' + f));

console.log(process.exitCode === 1 ? "\nSOME TESTS FAILED" : "\nALL DEMO ENGINE TESTS PASSED");
process.exit(process.exitCode || 0);
