use std::path::Path;

use agentsec_config::{ProjectConfig, Suite, Target};
use agentsec_core::ExitCode;
use clap::Parser;
use owo_colors::OwoColorize;

mod cli;
mod commands;
mod network_policy;
mod pipeline;
mod templates;

use cli::{Cli, Command};
use templates::{
    DATA_LEAKAGE_BASIC_SUITE, OUTPUT_HANDLING_BASIC_SUITE, PROMPT_INJECTION_BASIC_SUITE,
    SYSTEM_PROMPT_LEAKAGE_BASIC_SUITE,
};

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    let exit_code = match run(args).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{}: {:?}", "Error".red().bold(), e);
            ExitCode::RuntimeError
        }
    };
    std::process::exit(exit_code.code());
}

async fn run(args: Cli) -> anyhow::Result<ExitCode> {
    match args.command {
        Command::Version => {
            println!("AgentSec v{}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::Success)
        }
        Command::Init { r#type } => commands::init::run(r#type),
        Command::Validate { config } => commands::validate::run(config),
        Command::Ci {
            config,
            out,
            format,
            fail_on,
            baseline,
            update_baseline,
        } => commands::ci::run(config, out, format, fail_on, baseline, update_baseline).await,
        Command::Scan {
            target,
            suite,
            config,
            out,
            format,
            fail_on,
            timeout,
        } => commands::scan::run(target, suite, config, out, format, fail_on, timeout).await,
        Command::Plugin(plugin_cmd) => commands::plugin::run(plugin_cmd).await,
    }
}

/// Loads a suite by id: first checking `suites/<id>.yml`/`.yaml` on disk,
/// then falling back to the built-in registry embedded in `templates.rs`.
pub fn load_suite(suite_id: &str) -> anyhow::Result<Suite> {
    let suite_path = Path::new("suites").join(format!("{}.yml", suite_id));
    let suite_path_yaml = Path::new("suites").join(format!("{}.yaml", suite_id));
    let path_to_load = if suite_path.exists() {
        Some(suite_path)
    } else if suite_path_yaml.exists() {
        Some(suite_path_yaml)
    } else {
        None
    };

    if let Some(path) = path_to_load {
        Suite::load(&path)
    } else {
        let content = match suite_id {
            "prompt-injection-basic" => Some(PROMPT_INJECTION_BASIC_SUITE),
            "system-prompt-leakage-basic" => Some(SYSTEM_PROMPT_LEAKAGE_BASIC_SUITE),
            "output-handling-basic" => Some(OUTPUT_HANDLING_BASIC_SUITE),
            "data-leakage-basic" => Some(DATA_LEAKAGE_BASIC_SUITE),
            _ => None,
        };

        if let Some(yaml) = content {
            Suite::from_yaml(yaml)
                .map_err(|e| anyhow::anyhow!("failed to parse built-in suite {}: {}", suite_id, e))
        } else {
            anyhow::bail!(
                "Suite {} not found on disk or in built-in registry",
                suite_id
            )
        }
    }
}

/// Loads `agentsec.yml` at `config_path` if it exists, or returns a safe
/// ad-hoc default (network locked down to `deny_private_networks: true`)
/// if it doesn't. Shared by `agentsec scan` and `agentsec plugin run`,
/// which both need to work standalone without a project config.
pub fn load_project_config_or_adhoc_default(config_path: &Path) -> anyhow::Result<ProjectConfig> {
    if config_path.exists() {
        return ProjectConfig::load(config_path);
    }

    // No agentsec.yml means the user hasn't opted into any network
    // policy at all. Default to the SAFE posture for this ad-hoc path
    // specifically: deny private/loopback/link-local targets (e.g.
    // cloud metadata endpoints) unless they explicitly pass a config
    // that opts back out. This does not change the
    // NetworkSettings::default() used when a config file *is* present
    // but omits `network:`, to avoid silently changing behavior for
    // existing configs.
    eprintln!(
        "{}: no agentsec.yml found; running ad-hoc scan with deny_private_networks=true. \
         Use a config file to target private/internal hosts intentionally.",
        "Warning".yellow().bold()
    );
    Ok(ProjectConfig {
        version: "1".to_string(),
        project: agentsec_config::project::ProjectMeta {
            name: "ad-hoc-scan".to_string(),
            environment: Some("development".to_string()),
            owner: None,
        },
        targets: Vec::new(),
        suites: Vec::new(),
        ci: agentsec_config::project::CiSettings::default(),
        reports: agentsec_config::project::ReportSettings::default(),
        redaction: agentsec_config::project::RedactionSettings::default(),
        network: agentsec_config::project::NetworkSettings {
            allowed_hosts: Vec::new(),
            deny_private_networks: true,
        },
        evidence: agentsec_config::project::EvidenceSettings::default(),
        safety: agentsec_config::project::SafetySettings::default(),
        suppressions: None,
        baseline: None,
        telemetry: agentsec_config::project::TelemetrySettings::default(),
        policies: None,
        limits: None,
    })
}

/// Resolves a `--target` argument to a `Target`: a raw `http(s)://` URL
/// becomes a synthetic ad-hoc `HttpChat` target, otherwise it's looked up
/// by id in `project_config.targets`.
pub fn resolve_target(target: &str, project_config: &ProjectConfig) -> anyhow::Result<Target> {
    if target.starts_with("http://") || target.starts_with("https://") {
        Ok(Target {
            id: "ad-hoc-target".to_string(),
            kind: agentsec_config::target::TargetKind::HttpChat {
                base_url: target.to_string(),
                request: agentsec_config::target::HttpRequestSpec {
                    method: "POST".to_string(),
                    path: "/".to_string(),
                    headers: [("Content-Type".to_string(), "application/json".to_string())]
                        .into_iter()
                        .collect(),
                    body: serde_json::json!({
                        "message": "{{ input }}"
                    }),
                },
                response: agentsec_config::target::HttpResponseSpec {
                    answer_json_path: "$.answer".to_string(),
                    citations_json_path: None,
                    tool_calls_json_path: None,
                    trace_id_json_path: None,
                    retrieved_context_json_path: None,
                },
                capabilities: Default::default(),
            },
        })
    } else {
        project_config
            .targets
            .iter()
            .find(|t| t.id == target)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Target {} not found in config", target))
    }
}

/// Checks that every `${VAR}` reference in a target's config (base URL,
/// headers, request body, API key env) resolves to a set environment
/// variable, and records `MissingEnvVar` errors for any that don't.
pub fn validate_env_vars(
    config: &ProjectConfig,
    errors: &mut Vec<agentsec_config::ValidationError>,
) {
    let pattern = regex::Regex::new(r"\$\{([A-Za-z0-9_]+)\}").unwrap();
    for target in &config.targets {
        match &target.kind {
            agentsec_config::target::TargetKind::HttpChat {
                base_url, request, ..
            } => {
                let mut check_str = |s: &str| {
                    for cap in pattern.captures_iter(s) {
                        let var = &cap[1];
                        if std::env::var(var).is_err() {
                            errors.push(agentsec_config::ValidationError::MissingEnvVar {
                                target: target.id.clone(),
                                var: var.to_string(),
                            });
                        }
                    }
                };

                check_str(base_url);
                check_str(&request.path);
                for val in request.headers.values() {
                    check_str(val);
                }
                let body_str = request.body.to_string();
                check_str(&body_str);
            }
            agentsec_config::target::TargetKind::OpenaiCompatible {
                api_key_env,
                organization_env,
                ..
            } => {
                if std::env::var(api_key_env).is_err() {
                    errors.push(agentsec_config::ValidationError::MissingEnvVar {
                        target: target.id.clone(),
                        var: api_key_env.clone(),
                    });
                }
                if let Some(org_env) = organization_env {
                    if std::env::var(org_env).is_err() {
                        errors.push(agentsec_config::ValidationError::MissingEnvVar {
                            target: target.id.clone(),
                            var: org_env.clone(),
                        });
                    }
                }
            }
            _ => {}
        }
    }
}
