import test from 'node:test';
import assert from 'node:assert/strict';
import { poissonUpper, binomUpper, betaI, gammaP } from '../src/stats.js';
import { generateTelemetry, enumerateChains, CONTROLS, DAYS, EDGES, canonicalIPv4, isInternalIPv4, mulberry32, poissonSample } from '../src/scenario.js';
import { analyzeControls, buildInstance, solveExact, solveBrute, pruneDominated, paretoFrontier, entryPointBaseline, planSummary, replayControl, gate } from '../src/sever.js';

const T = generateTelemetry();
const chains = enumerateChains();
const A = analyzeControls(CONTROLS, T, DAYS);
const by = new Map(A.map((a) => [a.control.id, a]));
const close = (a, b, tol = 1e-3) => assert.ok(Math.abs(a - b) <= tol, `${a} vs ${b}`);

test('exact Poisson and Clopper-Pearson upper bounds match known values', () => {
  close(poissonUpper(0), 2.9957);
  close(poissonUpper(1), 4.7439);
  close(poissonUpper(10), 16.962);
  for (const n of [10, 100, 5000]) close(binomUpper(0, n), 1 - Math.pow(0.05, 1 / n), 1e-6);
  close(betaI(2, 3, 0.4) + betaI(3, 2, 0.6), 1, 1e-9); // I_x(a,b) = 1 - I_{1-x}(b,a)
  close(gammaP(1, 2), 1 - Math.exp(-2), 1e-9);
});

test('95% Poisson upper bound covers the true rate at >= 95% (simulation)', () => {
  const rng = mulberry32(7);
  for (const lambda of [0.5, 3, 12, 40]) {
    let cover = 0; const R = 4000;
    for (let i = 0; i < R; i++) if (poissonUpper(poissonSample(rng, lambda)) >= lambda) cover++;
    assert.ok(cover / R >= 0.94, `lambda ${lambda}: coverage ${cover / R}`);
  }
});

test('IPv4 canonicalization catches the encodings URL parsers accept', () => {
  for (const h of ['169.254.169.254', '2852039166', '0xA9FEA9FE', '0251.0376.0251.0376', '[::ffff:a9fe:a9fe]', '[::ffff:169.254.169.254]', '169.16689662'])
    assert.equal(canonicalIPv4(h.toLowerCase()), '169.254.169.254', h);
  assert.equal(canonicalIPv4('hooks.northwind-3pl.com'), null);
  assert.ok(isInternalIPv4('10.40.3.12') && isInternalIPv4('172.20.1.1') && !isInternalIPv4('172.32.0.1') && !isInternalIPv4('35.203.88.41'));
});

test('validated chains are exactly the entry-to-objective paths of the graph', () => {
  assert.equal(chains.length, 15);
  const edge = new Set(EDGES.map(([a, b]) => a + '>' + b));
  for (const c of chains) {
    assert.ok(c.steps[0].startsWith('E') && c.objective.startsWith('O'));
    const path = [...c.steps, c.objective];
    for (let i = 1; i < path.length; i++) assert.ok(edge.has(path[i - 1] + '>' + path[i]), c.id);
  }
});

test('telemetry generation is deterministic', () => {
  const T2 = generateTelemetry();
  for (const k of Object.keys(T)) assert.equal(T2[k].length, T[k].length, k);
});

test('replay counts match an independent recount from the raw logs', () => {
  const c02 = by.get('C02').replay;
  const billing = T['waf.quote-api'].filter((e) => !e.attack && e.client === '10.40.2.7').length;
  assert.equal(c02.k, billing);
  assert.equal(c02.n, T['waf.quote-api'].filter((e) => !e.attack).length);
  assert.equal(c02.perDay.reduce((a, b) => a + b, 0), c02.k);
  // literal-string rule misses encoded variants, so it does not sever E1
  const c01 = by.get('C01');
  assert.equal(c01.replay.attackMatched, 2);
  assert.equal(c01.replay.attackTotal, 7);
  assert.deepEqual(c01.replay.severs, []);
  assert.equal(c01.gate.verdict, 'PARTIAL');
  assert.deepEqual(by.get('C02').replay.severs, ['E1']);
});

test('synthesized exceptions never exclude a key the swarm used, and keep full efficacy', () => {
  const derived = A.filter((a) => a.derivedFrom);
  assert.ok(derived.length >= 4);
  for (const d of derived) {
    const c = d.control;
    const attackKeys = new Set(T[c.src].filter((e) => e.attack && c.steps.includes(e.step)).map((e) => c.key(e)));
    for (const k of c.excludeKeys) assert.ok(!attackKeys.has(k), `${c.id} excludes attack key ${k}`);
    assert.equal(d.replay.attackMatched, d.replay.attackTotal, c.id);
    assert.ok(d.replay.k <= by.get(d.derivedFrom).replay.k);
  }
  // no exception is offered on a dimension the attacker controls (legacy-auth users)
  assert.ok(!by.has('C10x'));
});

test('gate verdicts follow the thresholds', () => {
  assert.equal(by.get('C12').gate.verdict, 'AUTO-APPLY');
  assert.equal(by.get('C03').gate.verdict, 'STAGE FIRST');
  assert.equal(by.get('C14').gate.verdict, 'APPROVAL'); // zero collateral but needs a change ticket
  const fake = { id: 'Z', via: 'one-click', steps: ['E1'] };
  assert.equal(gate(fake, { severs: ['E1'], perDayUCB: 0.2 }).verdict, 'AUTO-APPLY');
  assert.equal(gate(fake, { severs: ['E1'], perDayUCB: 11 }).verdict, 'STAGE FIRST');
});

function randomInstance(rng, nc, nch, nsteps) {
  const steps = Array.from({ length: nsteps }, (_, i) => 'S' + i);
  const chains = Array.from({ length: nch }, (_, j) => ({ id: 'K' + j, steps: steps.filter(() => rng() < 0.35).concat(steps[j % nsteps]) })).map((c) => ({ ...c, steps: [...new Set(c.steps)] }));
  const cands = Array.from({ length: nc }, (_, i) => ({ id: 'C' + i, cost: Math.round(rng() * 20) / 4, point: 0, minutes: 5, steps: steps.filter(() => rng() < 0.25) })).filter((c) => c.steps.length);
  return { cands, chains };
}

test('branch-and-bound equals brute force on random instances (depth 1 and 2)', () => {
  const rng = mulberry32(99);
  let checked = 0;
  for (let t = 0; t < 60; t++) {
    const inst = randomInstance(rng, 11, 7, 8);
    for (const depth of [1, 2]) {
      const b = solveBrute(inst, depth), e = solveExact(inst, depth);
      assert.equal(e.feasible, b.feasible);
      if (b.feasible) { close(e.cost, b.cost, 1e-6); checked++; }
    }
  }
  assert.ok(checked > 40);
});

test('dominance pruning never changes the optimum', () => {
  const rng = mulberry32(5);
  for (let t = 0; t < 40; t++) {
    const inst = randomInstance(rng, 10, 6, 7);
    const full = solveBrute(inst, 1), pr = solveBrute({ ...inst, cands: pruneDominated(inst.cands) }, 1);
    assert.equal(full.feasible, pr.feasible);
    if (full.feasible) close(full.cost, pr.cost, 1e-6);
  }
});

test('scenario plan severs every chain and beats entry-point blocking', () => {
  for (const [mm, depth] of [[Infinity, 1], [10, 1], [60, 1], [Infinity, 2]]) {
    const s = solveExact(buildInstance(A, chains, { maxMinutes: mm }), depth);
    assert.ok(s.feasible);
    const p = planSummary(s.ids, A, chains);
    assert.equal(p.severed, chains.length);
    assert.ok(p.perChain.every((c) => c.severedSteps.length >= depth));
    assert.ok(s.minutes <= mm);
  }
  const opt = planSummary(solveExact(buildInstance(A, chains), 1).ids, A, chains);
  const base = entryPointBaseline(A, chains);
  assert.equal(base.severed, chains.length);
  assert.ok(opt.costUCB < base.costUCB && opt.k < base.k);
  // one-click-only deadline cannot be met at depth 2
  assert.equal(solveExact(buildInstance(A, chains, { maxMinutes: 10 }), 2).feasible, false);
});

test('Pareto frontier is monotone and ends at the depth-1 optimum', () => {
  const inst = buildInstance(A, chains);
  const F = paretoFrontier(inst);
  for (let m = 1; m < F.length; m++) assert.ok(F[m].cost >= F[m - 1].cost - 1e-12);
  close(F[F.length - 1].cost, solveExact(inst, 1).cost, 1e-6);
});

test('a replayed control with exclusions recomputes bounds from scratch', () => {
  const c = CONTROLS.find((x) => x.id === 'C16');
  const r = replayControl({ ...c, excludeKeys: ['hd-01', 'hd-02'] }, T, DAYS);
  assert.equal(r.k, 0);
  close(r.perDayUCB, poissonUpper(0) / DAYS, 1e-9);
});
