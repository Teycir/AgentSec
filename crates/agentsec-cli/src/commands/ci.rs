//! `agentsec ci` (spec 8.4): the primary CI workflow command — runs every
//! configured target/suite pair and writes reports.

use std::path::Path;

use owo_colors::OwoColorize;

use agentsec_config::ProjectConfig;
use agentsec_core::ExitCode;

use crate::load_suite;
use crate::pipeline::{run_scan_pipeline, PipelineOptions};
use crate::validate_env_vars;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    config: String,
    out: Option<String>,
    format: Option<Vec<String>>,
    fail_on: Option<String>,
    baseline: Option<String>,
    update_baseline: bool,
) -> anyhow::Result<ExitCode> {
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
    validate_env_vars(&project_config, &mut errors);

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

    let mut suites = Vec::new();
    for suite_id in &project_config.suites {
        let suite = load_suite(suite_id)?;
        suites.push(suite);
    }

    let targets = project_config.targets.clone();

    run_scan_pipeline(
        project_config,
        targets,
        suites,
        PipelineOptions {
            out_dir_opt: out,
            formats_opt: format,
            fail_on_opt: fail_on,
            baseline_opt: baseline,
            update_baseline,
            timeout_override: None,
        },
    )
    .await
}
