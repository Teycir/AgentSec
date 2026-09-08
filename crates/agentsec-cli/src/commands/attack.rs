//! `agentsec attack` (roadmap Milestone 2): runs a suite test's original
//! input plus deterministic mutations of it against a live target, and
//! reports any case where a mutant's assertion outcome differs from the
//! seed test's outcome — i.e. real evidence a mutation changed model
//! behavior, not just the string.

use std::path::Path;

use owo_colors::OwoColorize;

use agentsec_attacker::{mutator_by_name, AttackCase, MutationContext, ALL_MUTATOR_NAMES};
use agentsec_config::Assertion;
use agentsec_core::ExitCode;
use agentsec_scanners::assertion_eval;

use crate::{load_project_config_or_adhoc_default, load_suite, resolve_target};

/// Best-effort extraction of a canary/marker string from a seed test's
/// assertions, so `ContextInjectionMutator` can target the same marker
/// the test's own assertions check for. Only looks at the simple
/// Contains/NotContains cases the built-in suites actually use.
fn canary_hint(test: &agentsec_config::SuiteTest) -> Option<String> {
    test.assertions.iter().find_map(|a| match a {
        Assertion::NotContains { value } | Assertion::Contains { value } => Some(value.clone()),
        _ => None,
    })
}

pub async fn run(
    target: String,
    suite: String,
    mutators: Vec<String>,
    config: String,
    out: Option<String>,
) -> anyhow::Result<ExitCode> {
    let config_path = Path::new(&config);
    let project_config = load_project_config_or_adhoc_default(config_path)?;
    let resolved_target = resolve_target(&target, &project_config)?;
    let loaded_suite = load_suite(&suite)?;

    let selected: Vec<String> = if mutators.iter().any(|m| m == "all") {
        ALL_MUTATOR_NAMES.iter().map(|s| s.to_string()).collect()
    } else {
        mutators
    };

    let mut resolved_mutators = Vec::new();
    for name in &selected {
        match mutator_by_name(name) {
            Some(m) => resolved_mutators.push(m),
            None => {
                eprintln!(
                    "{}: unknown mutator '{}' (available: {})",
                    "Error".red().bold(),
                    name,
                    ALL_MUTATOR_NAMES.join(", ")
                );
                return Ok(ExitCode::InvalidConfig);
            }
        }
    }
    if resolved_mutators.is_empty() {
        eprintln!(
            "{}: no mutators selected. Use --mutators <names> or --mutators all.",
            "Error".red().bold()
        );
        return Ok(ExitCode::InvalidConfig);
    }

    let client = agentsec_runner::build_http_client(project_config.ci.timeout_seconds)?;
    let out_dir = out.unwrap_or_else(|| project_config.reports.output_dir.clone());
    std::fs::create_dir_all(&out_dir)?;

    let mut lineage_records = Vec::new();
    let mut flips = 0usize;

    for test in &loaded_suite.tests {
        println!(
            "Attacking {}::{} on {}...",
            loaded_suite.id.cyan(),
            test.id.yellow(),
            resolved_target.id.yellow()
        );

        // 1. Run the seed (unmutated) input to get the baseline outcome.
        let seed_response = match agentsec_runner::executor::execute(
            &client,
            &resolved_target,
            &test.input,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{}: seed execution failed: {}", "Error".red().bold(), e);
                continue;
            }
        };
        let seed_passed = test
            .assertions
            .iter()
            .all(|a| assertion_eval::evaluate(a, &seed_response).passed);

        println!(
            "  seed: {}",
            if seed_passed {
                "PASS".green().to_string()
            } else {
                "FAIL".red().to_string()
            }
        );

        let context = MutationContext {
            canary_hint: canary_hint(test),
        };

        // 2. Run each mutant and compare its outcome to the seed's.
        for mutator in &resolved_mutators {
            let cases: Vec<AttackCase> = mutator.mutate(test, &context);
            for case in cases {
                let response = match agentsec_runner::executor::execute(
                    &client,
                    &resolved_target,
                    &case.input,
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!(
                            "  {} mutant {} execution failed: {}",
                            "Error".red().bold(),
                            case.id,
                            e
                        );
                        continue;
                    }
                };
                let mutant_passed = test
                    .assertions
                    .iter()
                    .all(|a| assertion_eval::evaluate(a, &response).passed);

                let flipped = mutant_passed != seed_passed;
                if flipped {
                    flips += 1;
                }

                println!(
                    "  {} [{}]: {}{}",
                    case.mutator_name.cyan(),
                    case.id,
                    if mutant_passed {
                        "PASS".green().to_string()
                    } else {
                        "FAIL".red().to_string()
                    },
                    if flipped {
                        " (FLIPPED vs seed)".magenta().bold().to_string()
                    } else {
                        String::new()
                    }
                );

                lineage_records.push(serde_json::json!({
                    "attack_id": case.id,
                    "parent_test_id": case.parent_test_id,
                    "mutator": case.mutator_name,
                    "target_id": resolved_target.id,
                    "suite_id": loaded_suite.id,
                    "seed_passed": seed_passed,
                    "mutant_passed": mutant_passed,
                    "flipped_outcome": flipped,
                    "mutant_input": case.input,
                }));
            }
        }
    }

    let lineage_path = Path::new(&out_dir).join("attack-lineage.json");
    std::fs::write(
        &lineage_path,
        serde_json::to_string_pretty(&lineage_records)?,
    )?;
    println!(
        "\nAttack lineage written to '{}'. {} mutant(s) flipped outcome vs. their seed.",
        lineage_path.display().cyan(),
        flips.to_string().bold()
    );

    Ok(ExitCode::Success)
}
