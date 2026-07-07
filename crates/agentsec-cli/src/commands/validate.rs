//! `agentsec validate` (spec 8.3): validates configuration without running
//! any tests against a live target.

use std::path::Path;

use owo_colors::OwoColorize;

use agentsec_config::ProjectConfig;
use agentsec_core::ExitCode;

use crate::load_suite;
use crate::validate_env_vars;

pub fn run(config: String) -> anyhow::Result<ExitCode> {
    let config_path = Path::new(&config);
    if !config_path.exists() {
        eprintln!(
            "{}: config file {} does not exist",
            "Error".red().bold(),
            config
        );
        return Ok(ExitCode::InvalidConfig);
    }
    let project_config = match ProjectConfig::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: failed to load config: {}", "Error".red().bold(), e);
            return Ok(ExitCode::InvalidConfig);
        }
    };

    let mut errors = agentsec_config::validate_config(&project_config);
    validate_env_vars(&project_config, &mut errors);

    let mut known_suite_ids = vec![
        "prompt-injection-basic".to_string(),
        "system-prompt-leakage-basic".to_string(),
        "output-handling-basic".to_string(),
        "data-leakage-basic".to_string(),
        "rag-basic".to_string(),
        "agent-tool-basic".to_string(),
    ];
    if let Ok(entries) = std::fs::read_dir("suites") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "yml" || ext == "yaml" {
                        if let Some(stem) = path.file_stem() {
                            known_suite_ids.push(stem.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }
    }

    errors.extend(agentsec_config::validate_suite_ids(
        &project_config,
        &known_suite_ids,
    ));

    for suite_id in &project_config.suites {
        match load_suite(suite_id) {
            Ok(suite) => {
                errors.extend(agentsec_config::validate_suite(&suite));
            }
            Err(e) => {
                eprintln!(
                    "{}: failed to load suite {}: {}",
                    "Error".red().bold(),
                    suite_id,
                    e
                );
                return Ok(ExitCode::InvalidConfig);
            }
        }
    }

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

    println!("{}", "Configuration is valid!".green().bold());
    Ok(ExitCode::Success)
}
