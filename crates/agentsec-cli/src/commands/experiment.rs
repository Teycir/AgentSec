//! `agentsec experiment run` / `agentsec experiment replay` (roadmap
//! Milestone 1): a thin reproducibility wrapper around the existing scan
//! pipeline. No mutation, no attacker — this milestone runs one existing
//! suite through an experiment.yml and proves the resulting manifest
//! (seed, config hash, agentsec version, target/model identifiers,
//! timestamp) is real and reusable.

use std::path::Path;

use owo_colors::OwoColorize;

use agentsec_config::{config_hash, ExperimentManifest, ExperimentSpec, ProjectConfig};
use agentsec_core::ExitCode;

use crate::pipeline::{run_scan_pipeline, PipelineOptions};
use crate::{load_suite, resolve_target};

/// Extracts a human-readable model identifier from a target, when it has
/// one. `openai-compatible` targets (the ones actually used against Ollama)
/// carry a `model` field; other target kinds don't have an equivalent, so
/// the manifest simply omits it rather than guessing.
fn target_model(target: &agentsec_config::Target) -> Option<String> {
    match &target.kind {
        agentsec_config::TargetKind::OpenaiCompatible { model, .. } => Some(model.clone()),
        _ => None,
    }
}

pub async fn run(path: String, config: String, out: Option<String>) -> anyhow::Result<ExitCode> {
    let experiment_path = Path::new(&path);
    if !experiment_path.exists() {
        eprintln!(
            "{}: experiment file {} does not exist",
            "Error".red().bold(),
            path
        );
        return Ok(ExitCode::InvalidConfig);
    }
    let raw_yaml = std::fs::read_to_string(experiment_path)?;
    let spec = ExperimentSpec::from_yaml(&raw_yaml)
        .map_err(|e| anyhow::anyhow!("failed to parse experiment {}: {}", path, e))?;

    let config_path = Path::new(&config);
    if !config_path.exists() {
        eprintln!(
            "{}: config file {} does not exist",
            "Error".red().bold(),
            config
        );
        return Ok(ExitCode::InvalidConfig);
    }
    let project_config = ProjectConfig::load(config_path)?;

    let mut errors = agentsec_config::validate_config(&project_config);
    crate::validate_env_vars(&project_config, &mut errors);
    if !errors.is_empty() {
        eprintln!(
            "{}: validation failed with {} errors:",
            "Error".red().bold(),
            errors.len()
        );
        for err in errors {
            eprintln!("  - {}", err);
        }
        return Ok(ExitCode::InvalidConfig);
    }

    let target = resolve_target(&spec.target, &project_config)?;
    let suite = load_suite(&spec.suite)?;

    let model = target_model(&target);
    let suite_id = suite.id.clone();
    let suite_version = suite.version.clone();
    let target_id = target.id.clone();

    let run_id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now();

    println!(
        "Running experiment {} ({} against {})...",
        spec.experiment.id.cyan(),
        suite_id.cyan(),
        target_id.yellow()
    );

    let out_dir = out
        .clone()
        .unwrap_or_else(|| project_config.reports.output_dir.clone());

    let exit_code = run_scan_pipeline(
        project_config,
        vec![target],
        vec![suite],
        PipelineOptions {
            out_dir_opt: out,
            formats_opt: None,
            fail_on_opt: None,
            baseline_opt: None,
            update_baseline: false,
            timeout_override: Some(spec.execution.timeout_seconds),
        },
    )
    .await?;

    let manifest = ExperimentManifest {
        agentsec_version: env!("CARGO_PKG_VERSION").to_string(),
        experiment_id: spec.experiment.id.clone(),
        run_id,
        seed: spec.execution.seed,
        target_id,
        target_model: model,
        suite_id,
        suite_version,
        config_hash: config_hash(&raw_yaml),
        timestamp,
    };

    let manifest_path = Path::new(&out_dir).join("experiment-result.json");
    if let Some(parent) = manifest_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;
    println!(
        "Experiment manifest written to '{}'.",
        manifest_path.display().cyan()
    );

    Ok(exit_code)
}

pub async fn replay(
    result_path: String,
    config: String,
    out: Option<String>,
) -> anyhow::Result<ExitCode> {
    let result_file = Path::new(&result_path);
    if !result_file.exists() {
        eprintln!(
            "{}: experiment result file {} does not exist",
            "Error".red().bold(),
            result_path
        );
        return Ok(ExitCode::InvalidConfig);
    }
    let raw = std::fs::read_to_string(result_file)?;
    let original: ExperimentManifest = serde_json::from_str(&raw).map_err(|e| {
        anyhow::anyhow!("failed to parse experiment manifest {}: {}", result_path, e)
    })?;

    let config_path = Path::new(&config);
    let project_config = ProjectConfig::load(config_path)?;
    let target = resolve_target(&original.target_id, &project_config)?;
    let suite = load_suite(&original.suite_id)?;

    println!(
        "Replaying experiment {} ({} against {})...",
        original.experiment_id.cyan(),
        original.suite_id.cyan(),
        original.target_id.yellow()
    );

    let replayed_model = target_model(&target);
    let replayed_suite_version = suite.version.clone();

    let exit_code = run_scan_pipeline(
        project_config,
        vec![target],
        vec![suite],
        PipelineOptions {
            out_dir_opt: out,
            formats_opt: None,
            fail_on_opt: None,
            baseline_opt: None,
            update_baseline: false,
            timeout_override: None,
        },
    )
    .await?;

    // Confirm identity, not model output: a live model call is not
    // bit-for-bit reproducible even with a seed, so replay only checks
    // that this run targeted the same model/suite as the original —
    // per the roadmap's Milestone 1 validation gate.
    let mut mismatches = Vec::new();
    if replayed_model != original.target_model {
        mismatches.push(format!(
            "target_model: original={:?} replay={:?}",
            original.target_model, replayed_model
        ));
    }
    if replayed_suite_version != original.suite_version {
        mismatches.push(format!(
            "suite_version: original={} replay={}",
            original.suite_version, replayed_suite_version
        ));
    }

    if mismatches.is_empty() {
        println!(
            "{}: replay targeted the same model ({:?}) and suite version ({}) as the original run.",
            "Confirmed".green().bold(),
            original.target_model,
            original.suite_version
        );
    } else {
        eprintln!(
            "{}: replay diverged from the original manifest:",
            "Warning".yellow().bold()
        );
        for m in &mismatches {
            eprintln!("  - {}", m);
        }
    }

    Ok(exit_code)
}
