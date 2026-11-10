// Sever Plan core: replay each candidate control against production telemetry,
// bound its collateral, synthesize safe scoped exceptions, gate auto-apply,
// and pick the minimum-collateral set of controls that severs every validated
// kill chain (exact branch-and-bound, optional defense-in-depth).
import { poissonUpper, binomUpper } from './stats.js';

export const DEFAULTS = {
  conf: 0.95,
  autoMaxPerDay: 0.25,      // auto-apply only if the 95% upper bound on legit blocks/day is below this
  approvalMaxPerDay: 10,    // above this, stage the control first
  maxExceptionKeys: 3,
};

// ---- 1. replay -------------------------------------------------------------
export function replayControl(control, telemetry, days, opts = {}) {
  const conf = opts.conf ?? DEFAULTS.conf;
  const events = telemetry[control.src] || [];
  const excluded = new Set(control.excludeKeys || []);
  const isExcluded = (e) => excluded.size > 0 && control.key && excluded.has(control.key(e));
  let n = 0, k = 0;
  const perDay = new Array(days).fill(0);
  const entities = new Map();
  const legitKeys = new Map();
  const attackByStep = {};
  for (const e of events) {
    if (e.attack) {
      if (!control.steps.includes(e.step)) continue;
      const s = (attackByStep[e.step] = attackByStep[e.step] || { total: 0, matched: 0, missed: [] });
      s.total++;
      if (control.match(e) && !isExcluded(e)) s.matched++; else s.missed.push(e);
      continue;
    }
    n++;
    if (!control.match(e) || isExcluded(e)) continue;
    k++;
    perDay[e.d]++;
    const ent = control.entity ? control.entity(e) : 'event';
    entities.set(ent, (entities.get(ent) || 0) + 1);
    if (control.key) { const kk = control.key(e); legitKeys.set(kk, (legitKeys.get(kk) || 0) + 1); }
  }
  // a control severs a step only if it blocks every recorded attack variant of that step
  const severs = control.steps.filter((s) => attackByStep[s] && attackByStep[s].total > 0 && attackByStep[s].matched === attackByStep[s].total);
  const totalA = Object.values(attackByStep).reduce((a, s) => a + s.total, 0);
  const matchedA = Object.values(attackByStep).reduce((a, s) => a + s.matched, 0);
  return {
    id: control.id,
    n, k, days,
    perDay,
    perDayPoint: k / days,
    perDayUCB: poissonUpper(k, conf) / days,
    rateUCB: binomUpper(k, n, conf),
    entities: [...entities.entries()].sort((a, b) => b[1] - a[1]),
    legitKeys: [...legitKeys.entries()].sort((a, b) => b[1] - a[1]),
    attackByStep,
    efficacy: totalA ? matchedA / totalA : 0,
    attackTotal: totalA,
    attackMatched: matchedA,
    severs,
  };
}

// ---- 2. scoped-exception synthesis ----------------------------------------
// If a few exception keys explain the legit collateral and none of them ever
// appears in the swarm's recorded attempts, propose the control with those keys
// excluded and re-replay it (efficacy must stay at 100%).
export function synthesizeException(control, replay, telemetry, days, opts = {}) {
  const maxKeys = opts.maxExceptionKeys ?? DEFAULTS.maxExceptionKeys;
  if (!control.key || replay.k === 0 || replay.severs.length === 0) return null;
  const attackKeys = new Set();
  for (const e of telemetry[control.src] || []) if (e.attack && control.steps.includes(e.step)) attackKeys.add(control.key(e));
  const chosen = [];
  let covered = 0;
  for (const [key, count] of replay.legitKeys) {
    if (chosen.length >= maxKeys) break;
    if (attackKeys.has(key)) continue;
    chosen.push(key); covered += count;
  }
  if (!chosen.length || covered / replay.k < 0.9) return null;
  const derived = { ...control, id: control.id + 'x', baseId: control.id, excludeKeys: chosen, name: control.name, exceptionNote: 'except ' + chosen.join(', ') };
  const r = replayControl(derived, telemetry, days, opts);
  if (r.severs.length !== replay.severs.length) return null;
  return { control: derived, replay: r };
}

// ---- 3. auto-apply gate ---------------------------------------------------
export function gate(control, replay, opts = {}) {
  const autoMax = opts.autoMaxPerDay ?? DEFAULTS.autoMaxPerDay;
  const apprMax = opts.approvalMaxPerDay ?? DEFAULTS.approvalMaxPerDay;
  if (replay.severs.length === 0) return { verdict: 'PARTIAL', reason: `misses ${replay.attackTotal - replay.attackMatched} of ${replay.attackTotal} recorded variants` };
  if (control.via === 'one-click' && replay.perDayUCB <= autoMax) return { verdict: 'AUTO-APPLY', reason: `${replay.k} legit matches in ${replay.days}d` };
  if (replay.perDayUCB <= apprMax) return { verdict: 'APPROVAL', reason: control.via === 'one-click' ? 'collateral above auto threshold' : 'change ticket required' };
  return { verdict: 'STAGE FIRST', reason: `up to ${replay.perDayUCB.toFixed(0)} legit blocks/day` };
}

// ---- 4. analysis of the whole candidate set --------------------------------
export function analyzeControls(controls, telemetry, days, opts = {}) {
  const out = [];
  for (const c of controls) {
    const r = replayControl(c, telemetry, days, opts);
    out.push({ control: c, replay: r, gate: gate(c, r, opts) });
    const x = synthesizeException(c, r, telemetry, days, opts);
    if (x) out.push({ control: x.control, replay: x.replay, gate: gate(x.control, x.replay, opts), derivedFrom: c.id });
  }
  return out;
}

// ---- 5. optimization ------------------------------------------------------
// Candidate i covers chain j if it severs some step of j. depth=1: every chain
// needs one severed step; depth=2: two distinct severed steps per chain.
export function buildInstance(analysis, chains, { maxMinutes = Infinity, exclude = [] } = {}) {
  const cands = analysis
    .filter((a) => a.replay.severs.length > 0 && a.control.minutes <= maxMinutes && !exclude.includes(a.control.id))
    .map((a) => ({ id: a.control.id, cost: a.replay.perDayUCB, point: a.replay.perDayPoint, minutes: a.control.minutes, steps: a.replay.severs }));
  return { cands, chains: chains.map((c) => ({ id: c.id, steps: c.steps })) };
}

const stepCover = (cand, chain) => chain.steps.filter((s) => cand.steps.includes(s));

function coverageOf(selected, inst) {
  return inst.chains.map((ch) => {
    const steps = new Set();
    for (const c of selected) for (const s of stepCover(c, ch)) steps.add(s);
    return steps.size;
  });
}

const tieCost = (c) => c.cost + c.minutes * 1e-7;

// Remove candidates dominated by another (covers a superset of steps, costs no more, deploys no slower).
export function pruneDominated(cands) {
  return cands.filter((a, i) => !cands.some((b, j) => j !== i &&
    a.steps.every((s) => b.steps.includes(s)) && b.cost <= a.cost && b.minutes <= a.minutes &&
    (b.steps.length > a.steps.length || b.cost < a.cost || b.minutes < a.minutes || j < i)));
}

export function solveExact(inst, depth = 1) {
  const cands = pruneDominated(inst.cands).sort((a, b) => tieCost(a) - tieCost(b));
  const chains = inst.chains;
  // feasibility: each chain must have >= depth distinct severable steps among candidates
  const maxCov = coverageOf(cands, { chains });
  if (maxCov.some((c) => c < depth)) return { feasible: false, uncoverable: chains.filter((_, j) => maxCov[j] < depth).map((c) => c.id) };
  let best = null, bestCost = Infinity, nodes = 0;
  const chosen = [];
  const counts = chains.map(() => new Map()); // per chain: step -> multiplicity
  const covered = (j) => counts[j].size >= depth;
  const add = (c, sign) => chains.forEach((ch, j) => { for (const s of stepCover(c, ch)) { const m = (counts[j].get(s) || 0) + sign; if (m <= 0) counts[j].delete(s); else counts[j].set(s, m); } });
  function rec(i, cost) {
    nodes++;
    if (cost >= bestCost - 1e-12) return;
    const open = chains.findIndex((_, j) => !covered(j));
    if (open === -1) { bestCost = cost; best = [...chosen]; return; }
    if (i >= cands.length) return;
    // branch on candidates that help the first uncovered chain (keeps the tree small)
    const ch = chains[open];
    for (let t = i; t < cands.length; t++) {
      const c = cands[t];
      const helps = stepCover(c, ch).some((s) => !counts[open].has(s));
      if (!helps || chosen.includes(c)) continue;
      chosen.push(c); add(c, +1);
      rec(0, cost + tieCost(c));
      add(c, -1); chosen.pop();
    }
  }
  rec(0, 0);
  return { feasible: true, ids: best.map((c) => c.id).sort(), cost: best.reduce((a, c) => a + c.cost, 0), point: best.reduce((a, c) => a + c.point, 0), minutes: Math.max(...best.map((c) => c.minutes)), nodes, considered: cands.length };
}

export function solveBrute(inst, depth = 1) {
  const cands = inst.cands;
  let best = null, bestCost = Infinity;
  for (let mask = 1; mask < 1 << cands.length; mask++) {
    const sel = cands.filter((_, i) => mask & (1 << i));
    const cov = coverageOf(sel, inst);
    if (cov.some((c) => c < depth)) continue;
    const cost = sel.reduce((a, c) => a + tieCost(c), 0);
    if (cost < bestCost - 1e-12) { bestCost = cost; best = sel; }
  }
  if (!best) return { feasible: false };
  return { feasible: true, ids: best.map((c) => c.id).sort(), cost: best.reduce((a, c) => a + c.cost, 0) };
}

// Pareto frontier: least collateral needed to sever at least m chains, for every m.
export function paretoFrontier(inst) {
  const cands = pruneDominated(inst.cands);
  const L = cands.length;
  if (L > 22) throw new Error('too many candidates for exact frontier');
  const masks = cands.map((c) => inst.chains.reduce((m, ch, j) => (stepCover(c, ch).length ? m | (1 << j) : m), 0));
  const best = new Array(inst.chains.length + 1).fill(Infinity);
  const bestSel = new Array(inst.chains.length + 1).fill(null);
  best[0] = 0; bestSel[0] = [];
  const popcount = (x) => { let c = 0; while (x) { x &= x - 1; c++; } return c; };
  for (let mask = 1; mask < 1 << L; mask++) {
    let cov = 0, cost = 0;
    for (let i = 0; i < L; i++) if (mask & (1 << i)) { cov |= masks[i]; cost += cands[i].cost; }
    const m = popcount(cov);
    if (cost < best[m] - 1e-12) { best[m] = cost; bestSel[m] = cands.filter((_, i) => mask & (1 << i)).map((c) => c.id); }
  }
  // enforce monotonicity: severing >= m chains
  for (let m = best.length - 2; m >= 0; m--) if (best[m + 1] < best[m]) { best[m] = best[m + 1]; bestSel[m] = bestSel[m + 1]; }
  return best.map((cost, m) => ({ chains: m, cost, ids: bestSel[m] }));
}

// ---- 6. baselines ---------------------------------------------------------
// "Block at the entry point": for each chain, push the rule as written (no
// scoped exceptions) on its entry step, choosing the lowest point-estimate
// collateral among controls that sever that step.
export function entryPointBaseline(analysis, chains) {
  const ids = new Set();
  for (const ch of chains) {
    const entry = ch.steps[0];
    const opts = analysis.filter((a) => !a.derivedFrom && a.replay.severs.includes(entry)).sort((a, b) => a.replay.perDayPoint - b.replay.perDayPoint || a.control.minutes - b.control.minutes);
    if (opts.length) ids.add(opts[0].control.id);
  }
  return planSummary([...ids], analysis, chains);
}

export function planSummary(ids, analysis, chains) {
  const by = new Map(analysis.map((a) => [a.control.id, a]));
  const sel = ids.map((id) => by.get(id)).filter(Boolean);
  const perChain = chains.map((ch) => {
    const steps = new Set(); const ctl = [];
    for (const a of sel) { const s = ch.steps.filter((x) => a.replay.severs.includes(x)); if (s.length) { s.forEach((x) => steps.add(x)); ctl.push(a.control.id); } }
    return { id: ch.id, severedSteps: [...steps], controls: ctl };
  });
  // plan-level: dedupe events blocked by more than one selected control in the same source
  const k = sel.reduce((a, s) => a + s.replay.k, 0);
  return {
    ids: sel.map((a) => a.control.id),
    count: sel.length,
    costUCB: sel.reduce((a, s) => a + s.replay.perDayUCB, 0),
    pointPerDay: sel.reduce((a, s) => a + s.replay.perDayPoint, 0),
    k,
    minutes: sel.length ? Math.max(...sel.map((a) => a.control.minutes)) : 0,
    severed: perChain.filter((c) => c.severedSteps.length > 0).length,
    singlePoint: perChain.filter((c) => c.severedSteps.length === 1).length,
    perChain,
  };
}
