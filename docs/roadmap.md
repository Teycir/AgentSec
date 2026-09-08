# Roadmap: adversarial fuzzing evolution

Status of the "generative adversarial fuzzing" line item tracked in
[CHANGELOG.md's Unreleased section](../CHANGELOG.md#unreleased). Every
milestone gate below is a real command run against a live local Ollama
server (0.20.3) — no mocked model responses anywhere in this document.

Source spec: an internal proposal describing a multi-year research
platform (attacker LLM, attack-graph genealogy, coding-agent
benchmarks, model supply-chain scanning, Pareto analysis). That spec is
directionally sound but scopes 5-6 separable products as one project.
This roadmap keeps its milestone ordering (schema → mutators →
evaluator → attacker → benchmark → ...) but cuts scope hard: only
Milestones 0-4 are planned here. Milestones 5+ (benchmark engine,
Pareto frontier, coding-agent security, attack-graph visualization) are
deferred to a second roadmap, written only after M0-4 produce real data
worth benchmarking against.

## M0 — Ollama fixture: **done**

The repo had zero committed config pointing at a local model. Built and
validated `examples/ollama-local/` (config + experiment fixture + this
roadmap's evidence). Confirmed live round-trip against the
OpenAI-compatible endpoint before building anything on top of it.

Also fixed a real gap this surfaced: `api_key_env` was required even
for targets (like Ollama) that don't check it. Made it
`Option<String>` end-to-end — no `Authorization` header sent when
omitted, no env var required. Existing configs with a real key are
unaffected.

## M1 — Experiment runner: **done**

`agentsec-config::experiment` (`ExperimentSpec`, `ExperimentManifest`
with a SHA-256 config hash, seed, target/suite/model tracking) plus
`agentsec experiment run|replay`, both thin wrappers around the
existing `run_scan_pipeline` — no parallel execution engine.

**Live validation gate — passed twice** (once during initial build,
once from the promoted `examples/ollama-local/` fixture):
`agentsec experiment run` produced a real manifest (`seed: 42`,
`target_model: "gemma4:latest"`, a genuine SHA-256 hash, a real UUID
run ID). `agentsec experiment replay` made a second, independent live
call and confirmed it targeted the same model and suite version as the
original run.

## M2 — Deterministic mutators: **done**

New `agentsec-attacker` crate: a `Mutator` trait plus 5 deterministic
mutators (`roleplay`, `encoding`, `delimiter`, `context-injection`,
`instruction-reversal`), each unit-tested on fixed strings with no LLM
involved. `agentsec attack` runs a suite test's seed input plus every
mutant variant against a live target and reports any mutant whose
pass/fail outcome differs from the seed's, writing
`attack-lineage.json`.

**Live validation gate — passed, with real flips, on two model
families:**

- `gemma4:latest`: the `instruction-reversal` mutant flipped a failing
  prompt-injection seed to passing — the model failed to un-reverse
  the text well enough to also comply with the injected instruction.
- `granite4.2:latest`: both `encoding` (base64) and
  `instruction-reversal` flipped the same seed — two mutators broke
  the injection instead of one.

Full data and a per-mutator comparison table:
[`examples/ollama-local/README.md`](../examples/ollama-local/README.md#cross-family-finding-real-from-attack-lineagejson).

This is genuine evidence a mutation changed model behavior, captured
from real API calls — not asserted from a unit test.

## M3 — Generalized evaluator trait: **not started**

Before the attacker (M4), not after — deterministic assertions
(Contains/NotContains/JsonSchemaMatch, already in
`assertion_eval.rs`) and built-in scanner detectors need to sit behind
one `Evaluator` trait with a confidence level, wired to the
`Finding.confidence: f32` field that already exists in
`agentsec-core`. No LLM judge should exist until Level 1-3
(assertions → detectors → structured behavioral checks) is solid,
per the source spec's own insistence on keeping the
deterministic-vs-LLM-judged line clean.

**Planned live validation gate:** run the evaluator against the same
`attack-lineage.json` records M2 already produced (gemma4 and granite4
runs above) and confirm the confidence scores it assigns are
consistent with the pass/fail outcomes already observed — using real
recorded data, not synthetic fixtures.

## M4 — Local attacker LLM via the plugin protocol: **not started, but de-risked**

Ship as explicitly experimental/optional. Route through the existing
subprocess plugin protocol (`capabilities`/`scan`/`scan-output`)
rather than inventing a new integration path; sandbox via the existing
network policy (no filesystem/shell/secrets access for the attacker
process — this needs real engineering, not a config flag).

What M0-M2's live runs already established, concretely, ahead of
implementation:

- **Two genuinely different model families are locally available**:
  `gemma4:latest`/`gemma4:e4b` (Google, non-reasoning) and
  `granite4.2:latest` (IBM, reasoning/chain-of-thought by default) —
  confirmed via `ollama list`/`/api/tags`, not assumed.
- **Latency budget is asymmetric and must be planned per-model, not
  globally.** `gemma4:latest` cold-starts in ~30-50s and warms to
  <10s per call. `granite4.2:latest` is far more variable — observed
  single calls from ~45s up to ~4.5 minutes for one mutant, because it
  emits internal `<think>` reasoning before answering. A `300s`
  `ci.timeout_seconds` was sometimes still not enough for one specific
  mutant on one run, then sufficient on a re-run of the identical
  config — the variance is real and needs either a much larger budget
  or a retry policy, not a single fixed number.
- **granite4.2 hallucinates unprompted constraints.** A trivial sanity
  probe ("reply with exactly one word: ready") returned 948 tokens of
  invented adversarial framing the prompt never contained. For an
  attacker role this unpredictability could be a feature (novel attack
  framings); for a target role it's noise that needs either reasoning
  suppression in the prompt or a max-completion-token cap plus
  `</think>`-aware output extraction — currently `attack.rs` treats
  `TargetResponse` content verbatim, which will need revisiting before
  granite4 (or any reasoning model) is usable as an M4 *target*.
- **Cross-family pairing already surfaces real fragility
  differences**, not hypothetically: the M2 gate showed gemma4 and
  granite4 are broken by different mutators on the identical seed
  test. That is direct evidence a cross-family attacker (e.g. granite4
  attacking gemma4, or vice versa) is likely to find framings a
  same-family attacker would not — the core hypothesis M4 needs to
  test.
- **Non-determinism still conflicts with M1's own reproducibility
  claims** (unchanged from the original assessment): `seed`/
  `config_hash` pin the *experiment*, not the *model's* sampling.
  M4's manifest needs an explicit caveat rather than implying replay
  produces identical model output.

**Planned live validation gate:** `granite4.2:latest` attacking
`gemma4:latest` (or the reverse), through the plugin protocol, with a
timeout/retry policy sized to the latency numbers above, producing a
mutant that a same-family (M2, deterministic) attacker did not find.

## Deferred (separate future roadmap, written after M4 has real data)

- Benchmark engine + Pareto frontier — needs a real multi-run dataset
  to be meaningful; building the engine first risks producing numbers
  no one trusts.
- Coding-agent security benchmark — needs curated vulnerable-repo
  fixtures with known ground truth; a dataset-building project on its
  own, not a natural extension of the scanner core.
- Model supply-chain scanning — separable product, little code reuse
  from the scanner core.
- Attack-graph genealogy / HTML visualization — research-paper-grade
  feature with no MVP shortcut; revisit once M2-4 have produced enough
  real lineage records to visualize.
