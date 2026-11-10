import { STEPS, OBJECTIVES, EDGES, CONTROLS, DAYS, DAY0, generateTelemetry, enumerateChains } from './src/scenario.js';
import { analyzeControls, buildInstance, solveExact, planSummary, entryPointBaseline } from './src/sever.js';

// ---------------------------------------------------------------------------
// compute once
// ---------------------------------------------------------------------------
const telemetry = generateTelemetry();
const chains = enumerateChains();
const analysis = analyzeControls(CONTROLS, telemetry, DAYS);
const byId = new Map(analysis.map((a) => [a.control.id, a]));
const baseline = entryPointBaseline(analysis, chains);
const legitTotal = Object.values(telemetry).reduce((a, arr) => a + arr.filter((e) => !e.attack).length, 0);
const sources = Object.keys(telemetry).length;

const state = { depth: 1, maxMinutes: Infinity, manual: null, selected: null };
const qs = new URLSearchParams(location.search);
if (qs.get('depth') === '2') state.depth = 2;
if (qs.get('within')) state.maxMinutes = Number(qs.get('within')) || Infinity;
if (qs.get('sel')) state.selected = qs.get('sel');

const fmt = (x, d = 0) => x.toLocaleString('en-US', { minimumFractionDigits: d, maximumFractionDigits: d });
const fmtRate = (x) => (x < 10 ? fmt(x, 2) : fmt(x, 0));
const fmtMin = (m) => (m >= 1440 ? `${fmt(m / 1440)} days` : m >= 60 ? `${fmt(m / 60, m % 60 ? 1 : 0)} hr` : `${m} min`);
const badgeCls = { 'AUTO-APPLY': 'b-auto', APPROVAL: 'b-appr', 'STAGE FIRST': 'b-stage', PARTIAL: 'b-part' };
const badge = (v) => `<span class="badge ${badgeCls[v]}">${v}</span>`;
const $ = (id) => document.getElementById(id);

function solve(depth, maxMinutes) {
  const inst = buildInstance(analysis, chains, { maxMinutes });
  return solveExact(inst, depth);
}

function currentPlan() {
  let opt = solve(state.depth, state.maxMinutes);
  let fallback = null;
  if (!opt.feasible) { fallback = opt.uncoverable; opt = solve(1, state.maxMinutes); }
  const ids = state.manual ? [...state.manual] : opt.ids;
  return { opt, fallback, plan: planSummary(ids, analysis, chains), optPlan: planSummary(opt.ids, analysis, chains) };
}

// ---------------------------------------------------------------------------
// render
// ---------------------------------------------------------------------------
function render() {
  const { opt, fallback, plan, optPlan } = currentPlan();
  if (!state.selected || !byId.has(state.selected)) state.selected = plan.ids[0];
  renderHeader(plan);
  renderStats(plan);
  renderGraph(plan);
  renderPlan(plan, optPlan, fallback);
  renderTable(plan);
  renderFrontier();
  renderDetail();
  if (window.lucide) window.lucide.createIcons();
}

function renderHeader(plan) {
  $('nav-chains').textContent = chains.length;
  $('replay-chip').textContent = `Replay: Oct 22 to Nov 4 · ${sources} sources · ${fmt(legitTotal)} events`;
  $('subline').textContent = `The smallest-collateral set of compensating controls that cuts every validated kill chain from HA-1104. Each candidate rule is replayed against ${DAYS} days of your own telemetry before it ships, so you see who it would have blocked.`;
}

function renderStats(plan) {
  const nAuto = plan.ids.filter((id) => byId.get(id).gate.verdict === 'AUTO-APPLY').length;
  const entries = new Set(chains.map((c) => c.steps[0])).size;
  const objs = new Set(chains.map((c) => c.objective)).size;
  const cells = [
    ['Validated kill chains', `${chains.length}`, `${entries} entry points · ${objs} objectives`],
    ['Severed by plan', `${plan.severed}<small>/ ${chains.length}</small>`, state.depth === 2 ? `${plan.perChain.filter((c) => c.severedSteps.length >= 2).length} cut at 2+ steps` : `${plan.singlePoint} rely on one control`],
    ['Controls in plan', `${plan.count}`, `entry-point blocking: ${baseline.count}`],
    ['Legit blocks in replay', `${fmt(plan.k)}`, `entry-point blocking: ${fmt(baseline.k)}`],
    ['Blocks / day, 95% bound', `≤${fmtRate(plan.costUCB)}`, `entry-point blocking: ≤${fmtRate(baseline.costUCB)}`],
    ['Time to sever', fmtMin(plan.minutes), `${nAuto} auto-apply · ${plan.count - nAuto} need approval`],
  ];
  $('stats').innerHTML = cells.map(([l, v, c]) => `<div class="stat"><div class="l">${l}</div><div class="v">${v}</div><div class="c">${c}</div></div>`).join('');
}

// ---- kill-chain graph ------------------------------------------------------
// Columns come from longest-path layering of the chain graph; row order within a
// column is fixed to keep crossings low for this graph.
const ROWS = { 1: ['E1', 'E2', 'E4', 'E5', 'E3'], 2: ['P1', 'P2', 'P4', 'P5', 'P8'], 3: ['P3', 'P6', 'P10', 'P9'], 4: ['P7', 'P11'], 5: ['O5', 'O1', 'O2', 'O4', 'O3'] };
const GW = 740, GH = 440;
function layout() {
  const layer = {};
  ['E1', 'E2', 'E3', 'E4', 'E5'].forEach((e) => (layer[e] = 1));
  let changed = true;
  while (changed) {
    changed = false;
    for (const [a, b] of EDGES) {
      if (b.startsWith('O')) continue;
      if (layer[a] && (layer[b] || 0) < layer[a] + 1) { layer[b] = layer[a] + 1; changed = true; }
    }
  }
  const maxL = Math.max(...Object.values(layer));
  Object.keys(OBJECTIVES).forEach((o) => (layer[o] = maxL + 1));
  const cols = {};
  for (const [n, l] of Object.entries(layer)) (cols[l] = cols[l] || []).push(n);
  for (const l of Object.keys(cols)) cols[l].sort((a, b) => (ROWS[l] || []).indexOf(a) - (ROWS[l] || []).indexOf(b));
  const xs = { 0: 38 };
  for (let l = 1; l <= maxL + 1; l++) xs[l] = 140 + ((l - 1) * 460) / maxL;
  const P = {};
  for (let l = 1; l <= maxL + 1; l++) {
    const list = cols[l];
    const span = Math.min(330, (list.length - 1) * 84);
    list.forEach((n, i) => (P[n] = { x: xs[l], y: 205 - span / 2 + (list.length === 1 ? 0 : (i * span) / (list.length - 1)) }));
  }
  P.ATT = { x: xs[0], y: 205 };
  return P;
}
const P = layout();

function wrap(text, max = 19) {
  const words = text.split(' '); const lines = []; let cur = '';
  for (const w of words) { if ((cur + ' ' + w).trim().length > max && cur) { lines.push(cur); cur = w; } else cur = (cur + ' ' + w).trim(); }
  if (cur) lines.push(cur);
  return lines.slice(0, 2);
}

function cube(x, y, s, cls) {
  const h = s * 0.5;
  const top = `${x},${y - s} ${x + s},${y - s + h} ${x},${y - s + 2 * h} ${x - s},${y - s + h}`;
  const left = `${x - s},${y - s + h} ${x},${y - s + 2 * h} ${x},${y + h} ${x - s},${y}`;
  const right = `${x + s},${y - s + h} ${x},${y - s + 2 * h} ${x},${y + h} ${x + s},${y}`;
  return `<g class="${cls}"><polygon points="${top}" class="ft"/><polygon points="${left}" class="fl"/><polygon points="${right}" class="fr"/></g>`;
}

function burst(cx, cy) {
  let s = '';
  for (let i = -2; i <= 2; i++) for (let j = -2; j <= 2; j++) {
    const x = cx + i * 9, y = cy + j * 9;
    if (i === 0 && j === 0) { s += `<rect x="${x - 2}" y="${y - 2}" width="4" height="4" fill="#e9e9e9"/>`; continue; }
    const ang = Math.atan2(j, i) * 180 / Math.PI;
    s += `<rect x="${x - 3.2}" y="${y - 1.4}" width="6.4" height="2.8" rx="0.6" fill="#e9e9e9" transform="rotate(${ang} ${x} ${y})"/>`;
  }
  return s;
}

function renderGraph(plan) {
  const severed = new Map(); // step -> [control ids]
  for (const id of plan.ids) for (const s of byId.get(id).replay.severs) { if (!severed.has(s)) severed.set(s, []); severed.get(s).push(id); }
  // attacker reach: walk each chain until the first severed step
  const reachEdge = new Set(), cutEdge = new Set(), reachNode = new Set(), reachObj = new Set();
  for (const ch of chains) {
    const path = ['ATT', ...ch.steps, ch.objective];
    for (let i = 1; i < path.length; i++) {
      const key = path[i - 1] + '>' + path[i];
      if (severed.has(path[i])) { cutEdge.add(key); break; }
      reachEdge.add(key); reachNode.add(path[i]);
      if (path[i].startsWith('O')) reachObj.add(path[i]);
    }
  }
  const openChains = chains.filter((c) => !c.steps.some((s) => severed.has(s))).length;
  $('graph-sub').textContent = openChains === 0
    ? `All ${chains.length} chains cut. Red shows how far the swarm still gets before a control stops it.`
    : `${openChains} of ${chains.length} chains still reach an objective.`;

  const allEdges = [...EDGES.filter(([a]) => a.startsWith('E')).map(([a]) => ['ATT', a]), ...EDGES];
  const uniq = [...new Map(allEdges.map((e) => [e.join('>'), e])).values()];
  const edgeSvg = uniq.map(([a, b]) => {
    const p = P[a], q = P[b];
    const x1 = p.x + (a === 'ATT' ? 26 : 12), x2 = q.x - (b.startsWith('O') ? 20 : 12);
    const dx = (x2 - x1) * 0.5;
    const key = a + '>' + b;
    const cls = reachEdge.has(key) ? 'e-open' : cutEdge.has(key) ? 'e-open' : 'e-dead';
    return `<path d="M${x1},${p.y} C${x1 + dx},${p.y} ${x2 - dx},${q.y} ${x2},${q.y}" class="edge ${cls}"/><circle cx="${x2}" cy="${q.y}" r="2.2" class="dot ${cls}"/>`;
  }).join('');

  const nodeSvg = Object.keys(STEPS).map((s) => {
    const { x, y } = P[s];
    const st = STEPS[s];
    const cut = severed.get(s);
    const reached = reachNode.has(s) || cut;
    const lines = wrap(st.label, 18);
    const ids = cut ? cut.join(' + ') : '';
    const sel = state.selected && byId.get(state.selected).control.steps.includes(s);
    return `<g class="node" data-step="${s}">
      ${sel ? `<circle cx="${x}" cy="${y}" r="17" class="sel-ring"/>` : ''}
      ${cube(x, y, 10, cut ? 'cube cut' : reached ? 'cube' : 'cube dead')}
      ${cut ? `<g transform="translate(${x + 13},${y - 15}) rotate(45)"><rect x="-4.5" y="-4.5" width="9" height="9" class="cutmark"/></g>` : ''}
      <text x="${x}" y="${y + 25}" text-anchor="middle" class="nl ${reached ? '' : 'nl-dead'}">${lines.map((l, i) => `<tspan x="${x}" dy="${i ? 13 : 0}">${l}</tspan>`).join('')}</text>
      <text x="${x}" y="${y + 25 + lines.length * 13}" text-anchor="middle" class="na ${cut ? 'cutl' : ''}">${cut ? 'CUT · ' + ids : st.asset}</text>
    </g>`;
  }).join('');

  const objSvg = Object.entries(OBJECTIVES).map(([o, ob]) => {
    const { x, y } = P[o];
    const hot = reachObj.has(o);
    const lines = wrap(ob.label, 16);
    return `<g class="obj ${hot ? 'hot' : 'safe'}">
      <polygon points="${x - 12},${y - 22} ${x + 12},${y - 10} ${x + 12},${y + 22} ${x - 12},${y + 10}" class="panel"/>
      <path d="M${x},${y - 8} l6.5,2.6 v4.6 c0,4.4 -2.8,7 -6.5,8.3 c-3.7,-1.3 -6.5,-3.9 -6.5,-8.3 v-4.6 z" class="shield"/>
      <line x1="${x}" y1="${y - 3.5}" x2="${x}" y2="${y + 1}" class="bang"/><line x1="${x}" y1="${y + 3.8}" x2="${x}" y2="${y + 4}" class="bang"/>
      <text x="${x + 20}" y="${y - 3}" class="ol">${lines.map((l, i) => `<tspan x="${x + 20}" dy="${i ? 13 : 0}">${l}</tspan>`).join('')}</text>
      <text x="${x + 20}" y="${y - 3 + lines.length * 13}" class="na">${hot ? ob.kind : 'UNREACHABLE'}</text>
    </g>`;
  }).join('');

  $('graph').innerHTML = `
    <style>
      .edge{fill:none;stroke-width:1.3;stroke-dasharray:5 4}
      .e-open{stroke:#c8120e;stroke-width:1.5}.dot.e-open{fill:#c8120e;stroke:none}
      .e-dead{stroke:rgba(255,255,255,.42)}.dot.e-dead{fill:rgba(255,255,255,.8);stroke:none}
      .cube .ft{fill:#c8120e}.cube .fl{fill:#a10d0a}.cube .fr{fill:#7f0a08}
      .cube.cut .ft{fill:#ffffff}.cube.cut .fl{fill:#dcdcdc}.cube.cut .fr{fill:#bdbdbd}
      .cube.dead .ft{fill:#f2f2f2}.cube.dead .fl{fill:#cfcfcf}.cube.dead .fr{fill:#b0b0b0}
      .cutmark{fill:#f7821a;stroke:#171717;stroke-width:1.5}
      .sel-ring{fill:none;stroke:#f7821a;stroke-width:1;stroke-dasharray:2 3}
      .nl,.na,.ol{paint-order:stroke;stroke:#191919;stroke-width:3.2px;stroke-linejoin:round}.nl{fill:#ededed;font-size:11px}.nl-dead{fill:#bdbdbd}
      .na{fill:#8a8a8a;font-size:9.5px;font-family:'Geist Mono',monospace;letter-spacing:.04em}
      .na.cutl{fill:#f7821a}
      .obj .panel{fill:none;stroke-width:1.8}.obj.hot .panel{stroke:#c8120e}.obj.safe .panel{stroke:rgba(255,255,255,.55)}
      .obj .shield{fill:none;stroke-width:1.4}.obj.hot .shield{stroke:#c8120e}.obj.safe .shield{stroke:rgba(255,255,255,.7)}
      .obj .bang{stroke-width:1.5;stroke-linecap:round}.obj.hot .bang{stroke:#c8120e}.obj.safe .bang{stroke:rgba(255,255,255,.7)}
      .ol{fill:#ededed;font-size:11px}.obj.safe .ol{fill:#d6d6d6}
      .att{fill:#bdbdbd;font-size:9.5px;font-family:'Geist Mono',monospace;letter-spacing:.05em}
    </style>
    ${edgeSvg}
    <g>${burst(P.ATT.x, P.ATT.y)}</g>
    <text x="${P.ATT.x}" y="${P.ATT.y + 40}" text-anchor="middle" class="att">SWARM</text>
    <text x="${P.ATT.x}" y="${P.ATT.y + 52}" text-anchor="middle" class="att">UNAUTH</text>
    ${nodeSvg}${objSvg}`;
  document.querySelectorAll('#graph .node').forEach((g) => g.addEventListener('click', () => {
    const s = g.dataset.step;
    const inPlan = plan.ids.find((id) => byId.get(id).control.steps.includes(s));
    const any = analysis.find((a) => a.control.steps.includes(s));
    state.selected = (inPlan || any.control.id); render();
  }));
}

// ---- plan list -------------------------------------------------------------
const verdictRank = { 'AUTO-APPLY': 0, APPROVAL: 1, 'STAGE FIRST': 2, PARTIAL: 3 };
function renderPlan(plan, optPlan, fallback) {
  const rows = plan.ids.map((id) => byId.get(id)).sort((a, b) => verdictRank[a.gate.verdict] - verdictRank[b.gate.verdict] || a.control.minutes - b.control.minutes);
  $('plan-sub').textContent = state.manual ? 'Custom selection (edited)' : `Exact optimum over ${analysis.filter((a) => a.replay.severs.length).length} effective candidates · ${state.depth === 2 ? 'two cuts per chain' : 'one cut per chain'} · within ${state.maxMinutes === Infinity ? 'any time' : fmtMin(state.maxMinutes)}`;
  $('plan-list').innerHTML = rows.map((a) => {
    const nCh = plan.perChain.filter((c) => c.controls.includes(a.control.id)).length;
    return `<div class="prow ${state.selected === a.control.id ? 'sel' : ''}" data-id="${a.control.id}">
      <div><div class="pn">${a.control.name}</div><div class="pm">${a.control.id} · <b>${a.control.integration}</b> · cuts ${nCh} chain${nCh === 1 ? '' : 's'} · ${fmtMin(a.control.minutes)}${a.control.exceptionNote ? ` · <span style="color:#f7821a">${a.control.exceptionNote}</span>` : ''}</div></div>
      <div class="pr">${badge(a.gate.verdict)}<div class="pm" style="margin-top:5px">${fmt(a.replay.k)} legit / ${DAYS}d</div></div>
    </div>`;
  }).join('');
  document.querySelectorAll('.prow').forEach((r) => r.addEventListener('click', () => { state.selected = r.dataset.id; render(); }));

  let foot = '';
  if (fallback) foot += `<div class="warn">No set of controls deployable within ${fmtMin(state.maxMinutes)} cuts ${fallback.join(', ')} twice; showing the one-cut plan.</div>`;
  const stage = rows.filter((a) => a.gate.verdict === 'STAGE FIRST');
  for (const a of stage) {
    const need = plan.perChain.filter((c) => c.controls.includes(a.control.id) && c.severedSteps.length <= state.depth).map((c) => c.id);
    const ent = a.replay.entities[0];
    foot += `<div class="warn" style="margin-bottom:6px">${a.control.id} is the only way to cut ${need.join(', ')} ${state.depth === 2 ? 'twice' : ''} but would block up to ${fmtRate(a.replay.perDayUCB)} legit requests/day (top: ${ent[0]}, ${fmt(ent[1])} in ${DAYS}d). Fix that dependency before pushing.</div>`;
  }
  const delta = plan.costUCB - optPlan.costUCB;
  foot += `<b>${plan.severed}/${chains.length}</b> chains cut. ${state.depth === 1 ? `${plan.singlePoint} depend on a single control; switch to 2 cuts for depth.` : `${plan.perChain.filter((c) => c.severedSteps.length >= 2).length} cut at two or more steps.`}`;
  if (state.manual) foot += ` Your edits cost <b>${delta >= 0 ? '+' : ''}${fmtRate(delta)}</b> blocks/day vs. the optimum. <a id="reset" style="color:#f7821a;cursor:pointer">Reset</a>`;
  $('plan-foot').innerHTML = foot;
  const r = $('reset'); if (r) r.addEventListener('click', () => { state.manual = null; render(); });
}

// ---- candidate table ---------------------------------------------------------
const stepOrder = Object.keys(STEPS);
function renderTable(plan) {
  const rows = [...analysis].sort((a, b) => stepOrder.indexOf(a.control.steps[0]) - stepOrder.indexOf(b.control.steps[0]) || a.control.id.localeCompare(b.control.id));
  const head = `<tr><th></th><th>ID</th><th>Control</th><th class="num">Variants</th><th class="num">Legit ${DAYS}d</th><th class="num">Per day ≤</th><th>Gate</th></tr>`;
  $('tbl').innerHTML = head + rows.map((a) => {
    const c = a.control, r = a.replay;
    const inPlan = plan.ids.includes(c.id);
    const eff = r.attackMatched === r.attackTotal ? `${r.attackMatched}/${r.attackTotal}` : `<span class="miss">${r.attackMatched}/${r.attackTotal}</span>`;
    return `<tr class="${a.derivedFrom ? 'derived' : ''} ${state.selected === c.id ? 'sel' : ''}" data-id="${c.id}">
      <td><span class="chk ${inPlan ? 'on' : ''} ${r.severs.length ? '' : 'na'}" data-toggle="${c.id}"></span></td>
      <td class="id">${c.id}<div class="integ" style="margin-top:2px">${c.steps.join(', ')}</div></td>
      <td><div class="nm">${c.name}</div><div class="integ" style="margin-top:2px">${c.integration} · ${c.via === 'one-click' ? 'one-click' : 'change ticket'} · ${fmtMin(c.minutes)}</div>${c.exceptionNote ? `<div class="ex">↳ synthesized exception: ${c.exceptionNote}</div>` : ''}</td>
      <td class="num">${eff}</td>
      <td class="num ${r.k ? '' : 'dim'}">${fmt(r.k)}</td>
      <td class="num">${fmtRate(r.perDayUCB)}</td>
      <td>${badge(a.gate.verdict)}</td>
    </tr>`;
  }).join('');
  document.querySelectorAll('#tbl tr[data-id]').forEach((tr) => tr.addEventListener('click', (ev) => {
    const tg = ev.target.closest('[data-toggle]');
    const id = tr.dataset.id;
    if (tg && byId.get(id).replay.severs.length) {
      const cur = new Set(state.manual || currentPlan().plan.ids);
      cur.has(id) ? cur.delete(id) : cur.add(id);
      state.manual = cur;
    }
    state.selected = id; render();
  }));
}

// ---- frontier: deadline vs collateral ----------------------------------------
function renderFrontier() {
  const D = [10, 15, 30, 60, 90, 120, 4320];
  const pts = D.map((m) => ({ m, s: solve(state.depth, m) }));
  const feas = pts.filter((p) => p.s.feasible);
  const rawMax = Math.max(baseline.costUCB, ...feas.map((p) => p.s.cost));
  const step = [1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000].find((st) => rawMax / st <= 4) || 5000;
  const maxY = Math.ceil((rawMax * 1.08) / step) * step;
  const X0 = 46, X1 = 420, Y0 = 18, Y1 = 178;
  const xi = (i) => X0 + (i * (X1 - X0)) / (D.length - 1);
  const yv = (v) => Y1 - (v / maxY) * (Y1 - Y0);
  const ticks = []; for (let v = 0; v <= maxY + 1e-9; v += step) ticks.push(v);
  let s = `<style>.ax{fill:#7d7d7d;font-size:9.5px;font-family:'Geist Mono',monospace}.gl{stroke:#262626}.fl{fill:none;stroke:#f7821a;stroke-width:1.6}.fp{fill:#f7821a}.bp{fill:none;stroke:#e0332d;stroke-width:1.4}.bl{fill:#e0332d;font-size:10px;font-family:'Geist Mono',monospace}.cur{fill:#171717;stroke:#fff;stroke-width:1.5}.lab{fill:#ededed;font-size:10px;font-family:'Geist Mono',monospace}</style>`;
  ticks.forEach((t) => { s += `<line x1="${X0}" x2="${X1}" y1="${yv(t)}" y2="${yv(t)}" class="gl"/><text x="${X0 - 8}" y="${yv(t) + 3}" text-anchor="end" class="ax">${t}</text>`; });
  D.forEach((m, i) => { s += `<text x="${xi(i)}" y="${Y1 + 16}" text-anchor="middle" class="ax">${m >= 1440 ? '3d' : m >= 60 ? m / 60 + 'h' : m + 'm'}</text>`; });
  let d = '';
  pts.forEach((p, i) => { if (!p.s.feasible) return; const y = yv(p.s.cost); d += d ? ` H${xi(i)} V${y}` : `M${xi(i)},${y}`; });
  if (d) s += `<path d="${d}" class="fl"/>`;
  pts.forEach((p, i) => {
    if (!p.s.feasible) { s += `<text x="${xi(i)}" y="${Y1 - 6}" text-anchor="middle" class="ax">n/a</text>`; return; }
    const isCur = (state.maxMinutes === p.m) || (state.maxMinutes === Infinity && p.m === 4320) || (state.maxMinutes === 60 && p.m === 60);
    s += `<circle cx="${xi(i)}" cy="${yv(p.s.cost)}" r="${isCur ? 4.5 : 3}" class="${isCur ? 'cur' : 'fp'}"/>`;
    if (i === 0 || pts[i - 1].s.feasible === false || Math.abs(pts[i - 1].s.cost - p.s.cost) > 0.01) s += `<text x="${xi(i) + 6}" y="${yv(p.s.cost) - 7}" class="lab">${fmtRate(p.s.cost)}</text>`;
  });
  // baseline marker at entry-point blocking (all entry rules are one-click, <= 10 min)
  const bi = D.findIndex((m) => m >= baseline.minutes);
  s += `<rect x="${xi(bi) - 4}" y="${yv(baseline.costUCB) - 4}" width="8" height="8" transform="rotate(45 ${xi(bi)} ${yv(baseline.costUCB)})" class="bp"/><text x="${xi(bi) + 10}" y="${yv(baseline.costUCB) + 4}" class="bl">entry-point blocking ≤${fmtRate(baseline.costUCB)}/day</text>`;
  s += `<text x="${X0}" y="${Y0 - 6}" class="ax">LEGIT BLOCKS/DAY, 95% BOUND</text><text x="${X1}" y="${Y1 + 30}" text-anchor="end" class="ax">DEPLOY DEADLINE</text>`;
  $('frontier').innerHTML = s;
  const f10 = pts[0].s, fAny = pts[pts.length - 1].s;
  $('front-sub').textContent = f10.feasible && fAny.feasible
    ? `Optimal plan at each deadline. One-click only (10 min) costs ≤${fmtRate(f10.cost)}/day; waiting for change tickets drops it to ≤${fmtRate(fAny.cost)}/day.`
    : 'Optimal plan at each deadline (n/a: no plan severs every chain that fast).';
}

// ---- replay detail -----------------------------------------------------------
function renderDetail() {
  const a = byId.get(state.selected);
  const c = a.control, r = a.replay;
  const base = a.derivedFrom ? byId.get(a.derivedFrom).replay : null;
  const maxBar = Math.max(1, ...r.perDay, ...(base ? base.perDay : []));
  const bw = 400 / DAYS;
  const bar = (v, i, fill) => `<rect x="${i * bw + 3}" y="${46 - (v / maxBar) * 40}" width="${bw - 6}" height="${Math.max(1, (v / maxBar) * 40)}" fill="${fill}"/>`;
  const bars = (base ? base.perDay.map((v, i) => bar(v, i, '#3a3a3a')).join('') : '') + r.perDay.map((v, i) => (v || !base ? bar(v, i, v ? '#f7821a' : '#2f2f2f') : '')).join('');
  const barNote = base ? `<div class="variant" style="margin-top:2px"><span><span style="color:#8a8a8a">■</span> ${a.derivedFrom} as written: ${fmt(base.k)} legit blocks</span><span><span style="color:#f7821a">■</span> with exception: ${fmt(r.k)}</span></div>` : '';
  const variants = [];
  for (const e of telemetry[c.src].filter((e) => e.attack && c.steps.includes(e.step))) {
    const desc = e.cb || e.path || e.cmd || e.user || e.token || e.src || e.proc || e.auth || e.ver || e.sa || '';
    const hit = c.match(e) && !(c.excludeKeys && c.key && c.excludeKeys.includes(c.key(e)));
    variants.push(`<div class="variant"><span>${desc}</span><span class="${hit ? '' : 'miss'}">${hit ? 'BLOCKED' : 'MISSED'}</span></div>`);
  }
  const uniqV = [...new Set(variants)].slice(0, 7);
  $('detail').innerHTML = `
    <div class="card-head"><div><div class="card-title">Replay · ${c.id}</div><div class="card-sub">${c.name}${c.exceptionNote ? ` <span style="color:#f7821a">${c.exceptionNote}</span>` : ''}</div></div>${badge(a.gate.verdict)}</div>
    <div class="d-body">
      <div class="d-row"><span>Enforcement point log</span><span>${c.src} · ${fmt(r.n)} legit events</span></div>
      <div class="d-row"><span>Legit events the rule matches</span><span>${fmt(r.k)} (${fmt(r.perDayPoint, 2)}/day)</span></div>
      <div class="d-row"><span>95% upper bound</span><span>${fmtRate(r.perDayUCB)}/day · rate ≤${(r.rateUCB * 100).toPrecision(2)}%</span></div>
      <div class="d-row"><span>Gate</span><span>${a.gate.reason}</span></div>
      <svg viewBox="0 0 400 58" style="width:100%;height:auto;margin-top:6px">${bars}<text x="0" y="57" style="fill:#676767;font:9px 'Geist Mono'">OCT 22</text><text x="400" y="57" text-anchor="end" style="fill:#676767;font:9px 'Geist Mono'">NOV 4</text></svg>${barNote}
      ${r.entities.length ? `<div class="d-sec">Who it would have blocked</div>${r.entities.slice(0, 3).map(([e, n]) => `<div class="variant"><span>${e}</span><span>${fmt(n)}</span></div>`).join('')}` : `<div class="d-sec">Who it would have blocked</div><div class="variant"><span>No legitimate traffic matched in ${DAYS} days</span><span></span></div>`}
      <div class="d-sec">Recorded swarm variants · ${r.attackMatched}/${r.attackTotal} blocked</div>${uniqV.join('')}
    </div>`;
}

// ---------------------------------------------------------------------------
// wiring
// ---------------------------------------------------------------------------
function seg(id, key, parse) {
  $(id).querySelectorAll('button').forEach((b) => b.addEventListener('click', () => {
    $(id).querySelectorAll('button').forEach((x) => x.classList.toggle('on', x === b));
    state[key] = parse(b.dataset.v); state.manual = null; render();
  }));
}
const syncSeg = (id, v) => $(id).querySelectorAll('button').forEach((x) => x.classList.toggle('on', x.dataset.v === String(v)));
syncSeg('seg-depth', state.depth); syncSeg('seg-time', state.maxMinutes);
seg('seg-depth', 'depth', Number);
seg('seg-time', 'maxMinutes', (v) => (v === 'Infinity' ? Infinity : Number(v)));
$('push-btn').addEventListener('click', () => {
  const { plan } = currentPlan();
  const auto = plan.ids.filter((id) => byId.get(id).gate.verdict === 'AUTO-APPLY');
  const t = $('toast');
  t.textContent = `Demo only. Would push ${auto.join(', ')} now and open approval requests for ${plan.ids.filter((id) => !auto.includes(id)).join(', ') || 'none'}.`;
  t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 3200);
});
render();
