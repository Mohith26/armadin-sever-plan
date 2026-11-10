// Regenerates data/summary.json from the seeded scenario (the page computes the
// same thing live in the browser; this file is for inspection and diffing).
import { writeFileSync } from 'node:fs';
import { generateTelemetry, enumerateChains, CONTROLS, DAYS, SEED } from '../src/scenario.js';
import { analyzeControls, buildInstance, solveExact, entryPointBaseline, planSummary } from '../src/sever.js';

const T = generateTelemetry(SEED);
const chains = enumerateChains();
const A = analyzeControls(CONTROLS, T, DAYS);
const plan = (mm, d) => { const s = solveExact(buildInstance(A, chains, { maxMinutes: mm }), d); return s.feasible ? planSummary(s.ids, A, chains) : { feasible: false, uncoverable: s.uncoverable }; };
const strip = (p) => (p.perChain ? { ...p, perChain: undefined } : p);
const out = {
  seed: SEED, days: DAYS,
  events: Object.fromEntries(Object.entries(T).map(([k, v]) => [k, { legit: v.filter((e) => !e.attack).length, attack: v.filter((e) => e.attack).length }])),
  chains: chains.map((c) => ({ id: c.id, path: [...c.steps, c.objective].join(' > ') })),
  controls: A.map((a) => ({ id: a.control.id, name: a.control.name, exception: a.control.exceptionNote || null, k: a.replay.k, perDayUCB: +a.replay.perDayUCB.toFixed(3), variants: `${a.replay.attackMatched}/${a.replay.attackTotal}`, gate: a.gate.verdict })),
  plans: { any_depth1: strip(plan(Infinity, 1)), any_depth2: strip(plan(Infinity, 2)), within10_depth1: strip(plan(10, 1)), within60_depth1: strip(plan(60, 1)), within10_depth2: strip(plan(10, 2)) },
  entryPointBaseline: strip(entryPointBaseline(A, chains)),
};
writeFileSync(new URL('../data/summary.json', import.meta.url), JSON.stringify(out, null, 1));
console.log(JSON.stringify(out.plans.any_depth1), '\nbaseline', JSON.stringify(out.entryPointBaseline));
