# Sever Plan: minimum-collateral compensating controls for validated kill chains

**Live demo:** https://mohith26.github.io/armadin-sever-plan/

An unofficial concept feature for [Armadin](https://www.armadin.com), built as a static page in Armadin's visual language. It answers the question that comes right after a hyperattack finds kill chains: *which compensating controls should we push right now, and which of them are safe to push without a human?*

Unofficial concept demo by Mohith Gajjela. Not affiliated with Armadin. Synthetic data.

## Why

Armadin's public material describes the post-finding loop as: validated kill chains, prioritized remediation, a one-click Falcon block per kill chain, and WAF compensating controls next, where "a key challenge ... is ensuring they don't block legitimate user activity" (today handled by testing in customer dev/staging environments). Two gaps follow from doing this one chain at a time:

1. **Chains share steps.** Fifteen chains do not need fifteen rules. The right unit is the *set* of controls, chosen jointly, so one cut on a shared step severs many chains and expensive rules are avoided when a cheaper cut exists elsewhere on the same chain.
2. **Collateral is measurable before shipping.** Every candidate rule has an enforcement point (WAF, Falcon, Entra ID, Kubernetes, firewall) that already logs production traffic. Replaying the rule's own predicate over those logs says exactly who it would have blocked, with an honest upper bound when it blocked nobody.

## What the page does

For a synthetic customer ("Meridian Freight") and one hyperattack campaign (15 validated kill chains across 5 entry points and 5 objectives, 20 candidate controls plus synthesized variants):

- **Replay.** Each control's enforcement predicate runs over 14 days of telemetry from its own log source (275k events across 15 sources). Output: legit events matched, per-day series, top affected entities.
- **Efficacy against recorded variants.** The same predicate runs over the swarm's recorded attempts on that step. A rule only counts as cutting a step if it blocks every recorded variant. Example: a WAF rule matching the literal string `169.254.169.254` blocks 2 of 7 recorded SSRF payloads (decimal, hex, octal and IPv4-mapped IPv6 encodings get through), so it is marked PARTIAL and never used; the canonicalizing rule blocks 7/7.
- **Exact upper bounds.** Collateral is reported as an exact one-sided 95% Poisson upper bound on legit blocks per day (and a Clopper-Pearson bound on the block rate). A rule that matched nothing in 14 days is reported as "at most 0.21 per day", not "zero".
- **Scoped-exception synthesis.** If at most three exception keys explain at least 90% of a rule's collateral, and none of those keys ever appears in the swarm's attempts, the rule is re-proposed with those keys excluded and replayed again (efficacy must stay at 100%). Exceptions are only offered on dimensions the attacker does not control (e.g. an internal client IP plus destination, an exact script path, a fixed vendor IP); never on user accounts for a password-spray step.
- **Auto-apply gate.** AUTO-APPLY only for one-click integrations whose 95% bound is at most 0.25 legit blocks/day and that block every recorded variant; APPROVAL up to 10/day or for change-ticket controls; STAGE FIRST above that.
- **Optimization.** Choose the set of controls that severs every validated chain (or every chain at two distinct steps, for depth) while minimizing the sum of per-control 95% bounds, subject to a deploy deadline. Solved exactly: dominance pruning plus branch-and-bound that branches only on controls that cut the first uncut chain.
- **Baseline and frontier.** Compared against "block every chain at its entry point with the rule as written", and plotted as the optimal collateral at each deploy deadline.

### Results on the demo seed (all computed by the page)

| Plan | Controls | Legit blocks in 14-day replay | 95% bound, blocks/day | Time to sever |
|---|---|---|---|---|
| Entry-point blocking (rules as written) | 5 | 1,371 | 105 | 10 min |
| Sever Plan, one cut, any deadline | 6 | 0 | 1.28 | 90 min |
| Sever Plan, one cut, within 10 min | 5 | 562 | 44 | 10 min |
| Sever Plan, two cuts per chain | 13 | 24,249 | 1,754 | 2 hr |

The two-cut row is a finding, not a success: one chain (SSRF to instance credentials to the data lake) can only be cut a second time by enforcing IMDSv2, which would break a legacy log shipper that calls IMDSv1 1,728 times a day. The page flags that dependency instead of hiding it.

## How it works (files)

- `src/scenario.js`: seeded generator (mulberry32, seed 20261104) for the chain graph, controls with real predicates, and 14 days of telemetry including the swarm's recorded attempts. Kill chains are enumerated from the graph, not typed in.
- `src/stats.js`: incomplete gamma/beta functions and exact Poisson / Clopper-Pearson bounds.
- `src/sever.js`: replay, exception synthesis, gate, instance building, dominance pruning, branch-and-bound, brute force (for tests), Pareto frontier, baseline.
- `app.js`, `index.html`, `styles.css`: the UI. Everything shown is computed in the browser at load.
- `scripts/generate.js`: writes `data/summary.json` for inspection.

## Tests

```
node --test test/*.test.js
```

13 tests: bound values against known constants, simulated coverage of the 95% Poisson bound, IPv4 canonicalization of encoded addresses, chain enumeration, determinism, replay counts vs. an independent recount of the raw logs, exception safety (no excluded key ever used by the swarm, efficacy stays 7/7), gate thresholds, branch-and-bound equals brute force on 120 random instances at depth 1 and 2, dominance pruning never changes the optimum, every scenario plan severs every chain within its deadline, and the Pareto frontier is monotone.

## Honest limitations

- **Synthetic data.** The environment, logs and attack traces are generated. Real enforcement points log different fields, sample traffic, and change over time.
- **No public Armadin UI exists.** The page uses Armadin's published visual system (kill-chain diagrams and stat chips from their product video and Kill Chains & Coffee walkthroughs, Geist / Geist Mono, their palette). Navigation and layout of the app shell are my guess.
- **Recorded variants are a sample.** Blocking every recorded variant does not prove a rule blocks every possible variant; it is a necessary condition. Retesting after deployment is still required.
- **The 14-day window can miss rare legit traffic** (month-end jobs, quarterly vendor access). The 95% bound covers sampling noise, not seasonality.
- **Objective = sum of per-control 95% bounds.** Conservative and additive (it charges each extra control for unseen collateral), not a joint bound on the plan.
- **Exception keys** are chosen by count, up to three; whether a dimension is attacker-controllable is set per control by hand.

## Novelty note

Checked Armadin's site and blog (platform, hyperattack, Kill Chains & Coffee episodes 1-7, the NVIDIA Agent Safety post, the Nov 2026 Opportunity Intelligence report), the Series B coverage describing one-click Falcon compensating controls and planned WAF controls, and partner posts (Palo Alto Unit 42, CrowdStrike Fal.Con). None describe choosing compensating controls jointly across chains or replaying a rule against production telemetry to bound collateral before auto-applying it. Adjacent prior art: attack-path tools such as XM Cyber's "choke points" rank fixes where many paths converge, and WAFs offer log-only / count modes for a single rule. The combination here (efficacy against the swarm's own recorded variants, exact collateral bounds from replay, safe exception synthesis, and an exact min-collateral cut with deadline and depth constraints) is the proposed contribution.
