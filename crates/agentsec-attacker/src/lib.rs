//! agentsec-attacker: deterministic adversarial mutation engine (roadmap
//! Milestone 2). No LLM attacker here — that's Milestone 4. This crate
//! transforms an existing suite test's `input` into mutated variants using
//! pure string transformations, so mutation correctness can be unit tested
//! without a live model call, while the mutators' actual usefulness is only
//! proven by running the mutants against a real target (see the `attack`
//! CLI command in agentsec-cli, and the roadmap's Milestone 2 validation
//! gate).

pub mod mutators;

use agentsec_config::SuiteTest;

/// One mutation candidate: a seed test's `input` transformed by a mutator,
/// with a parent pointer for lineage (roadmap's flat-parent version of the
/// spec's attack genealogy — not a full graph yet).
#[derive(Debug, Clone)]
pub struct AttackCase {
    /// Unique id for this specific mutant, e.g. `<test_id>::<mutator>::<n>`.
    pub id: String,
    /// The seed `SuiteTest.id` this mutant was derived from.
    pub parent_test_id: String,
    /// Which mutator produced this case.
    pub mutator_name: &'static str,
    /// The mutated input text sent to the target in place of the original.
    pub input: String,
}

/// Context passed to a mutator alongside the seed case. Kept minimal for
/// M2 (deterministic mutators don't need much); M4's attacker will likely
/// need a richer context (prior outcomes, objective) but that's out of
/// scope here.
#[derive(Debug, Clone, Default)]
pub struct MutationContext {
    /// Optional canary/marker string the seed test's assertions check for,
    /// when known — some mutators (e.g. context injection) use this to
    /// build a more realistic malicious-document payload.
    pub canary_hint: Option<String>,
}

/// A deterministic (or, in later milestones, model-driven) transformation
/// from one seed `SuiteTest` into zero or more `AttackCase` mutants.
pub trait Mutator {
    /// Machine-readable name, used in `AttackCase.mutator_name` and as the
    /// `--mutators` CLI selector.
    fn name(&self) -> &'static str;

    /// Produces mutant variants of `seed`. Implementations should be pure
    /// functions of `seed`/`context` for M2 mutators — no network calls,
    /// no randomness beyond what's needed to produce a stable, reviewable
    /// output — so unit tests can assert exact string output.
    fn mutate(&self, seed: &SuiteTest, context: &MutationContext) -> Vec<AttackCase>;
}

/// Looks up a built-in mutator by its CLI name (roadmap M2 list only).
pub fn mutator_by_name(name: &str) -> Option<Box<dyn Mutator>> {
    match name {
        "roleplay" => Some(Box::new(mutators::RoleplayMutator)),
        "encoding" => Some(Box::new(mutators::EncodingMutator)),
        "delimiter" => Some(Box::new(mutators::DelimiterMutator)),
        "context-injection" => Some(Box::new(mutators::ContextInjectionMutator)),
        "instruction-reversal" => Some(Box::new(mutators::InstructionReversalMutator)),
        _ => None,
    }
}

/// Names of every built-in M2 mutator, in a stable order — used by
/// `--mutators all` and for help text.
pub const ALL_MUTATOR_NAMES: [&str; 5] = [
    "roleplay",
    "encoding",
    "delimiter",
    "context-injection",
    "instruction-reversal",
];
