# UniGuard AI - SOC UI Transformation Report

## Read this first

Same constraint as every previous round: **this sandbox has no internet**,
so the FastAPI server has never been started here, and there is **no
real browser** to render this in. Everything below was verified as far
as that allows - JS syntax-checked with `node --check`, HTML tag balance
verified programmatically, every DOM id cross-referenced in both
directions (JS→HTML and HTML→JS, so both "missing element" and "dead
button" bugs get caught), and the demo engine's actual runtime behavior
tested under Node with 34 automated assertions. The one thing that
still needs a real browser is **visual/layout correctness** - CSS Grid
behavior, mobile breakpoints, and general "does it look right" cannot
be confirmed from here. Do the local run (bottom of this doc) before
judging day.

---

## 1. Files changed

- `app.py` - dashboard route now serves `static/index.html` (the new
  SPA shell) instead of the old single-file dashboard; added two new
  endpoints (`/api/ip-lookup/{ip}`, `/api/system`)
- `requirements.txt` - added `psutil` (for real System Health metrics)

## 2. Files created

Backend:
- Two new endpoints in `app.py` (see above)

Frontend (all new):
```
static/index.html
static/css/app.css          - shell layout, design tokens, compact mode
static/css/components.css   - cards, tables, badges, tabs, modal, etc.
static/css/pages.css        - per-page layout tweaks
static/js/api.js            - real API calls only, nothing fabricated
static/js/demo.js           - client-side simulation engine
static/js/charts.js         - Chart.js theming wrapper
static/js/navigation.js     - hash-based router
static/js/app.js            - bootstrap, central 1s tick loop
static/js/pages/dashboard.js
static/js/pages/traffic.js
static/js/pages/threats.js
static/js/pages/alerts.js
static/js/pages/investigation.js
static/js/pages/ip.js
static/js/pages/network.js
static/js/pages/ai.js
static/js/pages/health.js
static/js/pages/settings.js
static/js/pages/reports.js
```
Tests:
- `tests/test_demo_engine.js` (new - 34 assertions on the simulation engine)

Removed: `static/dashboard.html` (the old single-page dashboard) - its
functionality is fully superseded by `static/index.html`, not lost.
Nothing else was removed. `app.py`'s existing routes
(`/api/metrics`, `/api/traffic/recent`, `/api/mitigate`, `/api/health`,
`/api/reset`) are **unchanged** - only additive endpoints were added.

## 3. Pages implemented (all 11)

| # | Page | Depth |
|---|------|-------|
| 01 | Dashboard | Full - metric cards, traffic chart, threat distribution, recent threats, active incident |
| 02 | Live Traffic | Full - live flow log, pause/resume/clear/filter, honest N/A for fields HTTP monitoring doesn't have |
| 03 | Threats | Full - severity filter, click-through to Investigation |
| 04 | Alerts | Full - active/resolved split; Acknowledge/Resolve **disabled with explanation** in live mode (backend has no such concept - not faked) |
| 05 | Investigation | Full - tabs (Overview/Timeline/Behavior/Traffic/Evidence/Response), real MITIGATE ATTACK button with confirmation modal |
| 06 | IP Intelligence | Full - real lookup via new `/api/ip-lookup/{ip}` endpoint |
| 07 | Network Graph | Full - SVG graph, zoom controls, click-to-inspect; real observed IPs in live mode |
| 08 | AI Models | Full - real pipeline state, honest XGBoost disclaimer preserved |
| 09 | System Health | Full - real CPU/memory/disk via new `/api/system` (psutil) endpoint |
| 10 | Settings | Full - every control labeled real (wired) or display-only, no silent fakes |
| 11 | Reports | Full - Generate/Print/Export all genuinely functional (client-side, no backend changes needed) |

Sidebar navigation is a real hash-based router (`#/dashboard`,
`#/investigation`, etc.) - every menu item switches to a real page, not
just a color change. Verified: every page module is registered, every
route resolves, no dead nav items (checked programmatically).

## 4. API integrations

Existing (untouched):
- `GET /api/metrics` - polled every 1s in live mode by the central tick loop
- `GET /api/traffic/recent?limit=N` - used by Live Traffic page
- `POST /api/mitigate` - used by Investigation page's real Mitigate Attack button
- `POST /api/reset`
- `GET /api/health`

New (additive, reuses already-tested logic):
- `GET /api/ip-lookup/{ip}` - reuses the same `compute_ip_intel()` function
  already covered by existing tests, applied to any IP in the retained
  request log (not just the current incident's source)
- `GET /api/system` - real `psutil` CPU/memory/disk usage; returns
  `resource_data_available: false` honestly if psutil isn't present,
  rather than fabricating numbers

## 5. Demo mode implementation

`static/js/demo.js` is a self-contained client-side simulation engine.
Critical design choice: **it outputs data in the exact same JSON shape
as the real `/api/metrics` response** (same field names throughout), so
every page renders real or simulated data through identical code -
this was a deliberate way to minimize the risk of the two code paths
silently drifting apart.

Scenarios (matching the spec's numeric targets): `normal` (800-1800
req/s, risk 5-20), `suspicious` (ramping, risk 20→65), `dos` (ramping to
~7000 req/s, risk →94, CRITICAL), `mitigation` (traffic falls),
`recovery` (severity steps back down to NORMAL). Values move smoothly
toward scenario targets via interpolation plus small sine-wave jitter -
not random jumps every tick, per the spec.

The demo incident lifecycle mirrors the real `IncidentManager`'s
debounce pattern (2 consecutive non-normal windows before an incident
opens) and recovery condition, adapted for scenario-driven data. Every
piece of demo evidence text is explicitly prefixed `[SIMULATED]`.

**Tested:** `tests/test_demo_engine.js`, run under Node, actually
executes the engine through all 5 scenarios and the full mitigate→
recover lifecycle - 34 assertions, all passing. This is not just a
syntax check; it exercises real tick-by-tick state transitions.

## 6. Real vs simulated traffic behavior

- Mode toggle (header, top-right): 🟢 LIVE / 🟣 DEMO. Switching modes
  changes what the central tick loop feeds every page - real
  `/api/metrics` polling vs `UGDemo.tick()` + `UGDemo.getSnapshot()`.
- Every data-bearing row/card that can show either source carries an
  explicit `🟢 REAL` / `🟣 SIMULATED` badge (Live Traffic flow log,
  Investigation header, IP Intelligence result).
- The spec's "REAL + SIMULATED combined total" example (e.g. "4,238 =
  1,240 real + 2,998 simulated") was **not** implemented - the two
  modes are mutually exclusive data sources in this build (LIVE shows
  only real data, DEMO shows only simulated data), not blended. Mixing
  them would risk exactly the kind of ambiguity the spec explicitly
  warns against ("NEVER mix simulated data with real data without
  labeling it"), and building a correctly-labeled blended view is
  materially more work than this round covered. Flagging this as a
  deliberate scope cut, not an oversight.
- Real Termux traffic is never touched by the demo engine - it flows
  through the unchanged real backend and middleware exactly as before,
  and is unambiguously labeled `🟢 REAL` wherever it's displayed.

## 7. Termux commands (unchanged from previous rounds)

```bash
pkg update -y
pkg install python -y
python3 termux_test_client.py --url https://your-app.onrender.com --rate 20 --duration 60
```

## 8. Local run command

```bash
pip install -r requirements.txt
uvicorn app:app --reload
```
Then open `http://localhost:8000/dashboard` (serves the new SPA shell).

## 9. URLs / routes

- `GET /dashboard` → the SPA shell (`static/index.html`)
- Client-side routes (hash-based, all within that one page):
  `#/dashboard`, `#/traffic`, `#/threats`, `#/alerts`, `#/investigation`,
  `#/ip`, `#/network`, `#/ai`, `#/health`, `#/settings`, `#/reports`
- Backend API routes: unchanged existing five, plus `GET /api/ip-lookup/{ip}`
  and `GET /api/system` (new)

## 10. Testing performed

- All 37 existing backend regression checks re-run after every backend
  change - still 37/37 passing
- `psutil` calls executed directly in this sandbox against the real
  machine - confirmed real (non-fabricated) CPU/memory/disk numbers
- Every one of 16 JS files individually syntax-checked with `node --check`
- `static/index.html` tag balance verified programmatically (0 errors)
- **Bidirectional DOM-id cross-check**: every `getElementById` call in
  every JS file confirmed to exist in the HTML, AND every HTML element
  id confirmed to be referenced by some JS (catches both "will crash"
  bugs and "silently dead" bugs) - found and fixed one real dead-element
  bug this way (see below)
- Demo engine executed under Node through all 5 scenarios and a full
  mitigate→recover cycle - 34 assertions passing, including field-shape
  parity with the real API contract

**NOT tested (needs a real browser, still cannot do from this sandbox):**
- Actual visual rendering, CSS Grid/flex layout correctness
- Mobile breakpoint behavior at 320/375/412px
- Touch interaction quality
- Whether Chart.js actually renders correctly in the chart containers
- The live `uvicorn` server actually serving `/api/ip-lookup` and
  `/api/system` correctly end-to-end (reviewed, not executed - same
  gap as the rest of the FastAPI layer in every previous round)

## 11. Bugs found and fixed this round

- **Dead element**: the Investigation page's "Evidence" tab (`invEvidence2`)
  was never populated by any JS - found by the bidirectional id
  cross-check, fixed by mirroring the Overview tab's evidence list into it
- **Non-functional "real" setting**: Settings → Interface → Compact
  mode toggled a CSS class that had no styles defined - would have
  been a fake control despite being labeled "real." Fixed by adding
  actual compact-mode CSS rules.

## 12. Remaining limitations

- No blended REAL+SIMULATED view (see item 6) - intentional scope cut
- Live Traffic table shows `N/A` for destination IP, ports, and packet
  count in live mode, because this backend only ever had HTTP-level
  telemetry (no raw packet capture is possible on hosted PaaS - this
  was already true before this round, just now visible in more places)
- Threat Distribution donut shows severity breakdown in live mode
  (not the DDoS-like/Port-Scan/Brute-Force/C2 categories from the
  spec), because the real backend has no classifier that distinguishes
  those attack types - it only detects DoS-like patterns via
  rate/burst/concentration heuristics. The 5-category breakdown from
  the spec is shown only in demo mode, clearly labeled simulated.
- XGBoost is still not implemented anywhere in this backend - the AI
  Models page states this plainly, consistent with every previous round
- Mobile drawer sidebar, zoom controls, and other interactive elements
  are implemented and structurally sound but, again, never seen
  rendering in an actual browser from this sandbox
