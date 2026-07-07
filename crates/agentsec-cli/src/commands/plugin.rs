//! `agentsec plugin` (spec 8.8): external security-tool adapters that
//! speak the generic plugin protocol (spec section 21).
//!
//! `run` mirrors the reporting/fail-on behavior of `agentsec scan`
//! (spec 8.5) but sources findings from a plugin subprocess instead of
//! the native `agentsec-runner`/`agentsec-scanners` pipeline, since a
//! plugin scan doesn't produce per-test HTTP traffic AgentSec itself
//! drives — the plugin binary owns that.

use std::path::Path;

use owo_colors::OwoColorize;

use agentsec_core::{ExitCode, Severity};
use agentsec_integrations::plugin::PluginScanOutput;
use agentsec_integrations::{plugin, promptfoo};

use crate::cli::PluginCommand;
use crate::{load_project_config_or_adhoc_default, load_suite, resolve_target};

pub async fn run(command: PluginCommand) -> anyhow::Result<ExitCode> {
    match command {
        PluginCommand::List => run_list(),
        PluginCommand::Info { name } => run_info(&name).await,
        PluginCommand::Run {
            name,
            target,
            suite,
            config,
            out,
            format,
            fail_on,
            timeout,
        } => run_scan(name, target, suite, config, out, format, fail_on, timeout).await,
        PluginCommand::ValidateOutput { path } => run_validate_output(&path),
    }
}

/// Known plugin adapters built into this binary. Only `promptfoo` exists
/// today (garak/PyRIT are deferred — spec 25); listed as a small const
/// table rather than a single hardcoded string so adding the next
/// adapter is a one-line change here plus its own module.
const KNOWN_ADAPTERS: &[(&str, &str)] = &[(
    promptfoo::BINARY_NAME,
    "Promptfoo scan/redteam adapter (requires a `promptfoo` binary on PATH \
     implementing the AgentSec plugin protocol, spec section 21)",
)];

fn run_list() -> anyhow::Result<ExitCode> {
    println!("Known plugin adapters:\n");
    for (name, description) in KNOWN_ADAPTERS {
        println!("  {}  {}", name.cyan().bold(), description);
    }
    println!(
        "\nUse '{}' to check whether a plugin binary is installed and what it reports.",
        "agentsec plugin info <name>".bold()
    );
    Ok(ExitCode::Success)
}

async fn run_info(name: &str) -> anyhow::Result<ExitCode> {
    match plugin::run_capabilities(name).await {
        Ok(caps) => {
            println!("{}: {}", "name".bold(), caps.name);
            println!("{}: {}", "version".bold(), caps.version);
            println!(
                "{}: {}",
                "supported target types".bold(),
                if caps.supported_target_types.is_empty() {
                    "(none reported)".to_string()
                } else {
                    caps.supported_target_types.join(", ")
                }
            );
            println!(
                "{}: {}",
                "supported categories".bold(),
                if caps.supported_categories.is_empty() {
                    "(none reported)".to_string()
                } else {
                    caps.supported_categories.join(", ")
                }
            );
            println!(
                "{}: {}",
                "requires".bold(),
                if caps.requires.is_empty() {
                    "(none reported)".to_string()
                } else {
                    caps.requires.join(", ")
                }
            );
            Ok(ExitCode::Success)
        }
        Err(e) => {
            eprintln!(
                "{}: failed to get capabilities for plugin '{}': {}",
                "Error".red().bold(),
                name,
                e
            );
            Ok(ExitCode::RuntimeError)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_scan(
    name: String,
    target: String,
    suite: String,
    config: String,
    out: Option<String>,
    format: Option<Vec<String>>,
    fail_on: Option<String>,
    timeout: u64,
) -> anyhow::Result<ExitCode> {
    if name != promptfoo::BINARY_NAME {
        eprintln!(
            "{}: unknown plugin adapter '{}'. Known adapters: {}",
            "Error".red().bold(),
            name,
            KNOWN_ADAPTERS
                .iter()
                .map(|(n, _)| *n)
                .collect::<Vec<_>>()
                .join(", ")
        );
        return Ok(ExitCode::InvalidConfig);
    }

    let config_path = Path::new(&config);
    let project_config = load_project_config_or_adhoc_default(config_path)?;
    let resolved_target = resolve_target(&target, &project_config)?;
    let loaded_suite = load_suite(&suite)?;

    let run_id = uuid::Uuid::new_v4().to_string();
    let started_at = chrono::Utc::now();

    println!(
        "Running suite {} against target {} via plugin '{}'...",
        loaded_suite.name.cyan(),
        resolved_target.id.yellow(),
        name.cyan()
    );

    let findings =
        match promptfoo::run_scan(&run_id, &resolved_target, &loaded_suite, timeout).await {
            Ok(findings) => findings,
            Err(e) => {
                eprintln!(
                    "{}: plugin '{}' scan failed: {}",
                    "Error".red().bold(),
                    name,
                    e
                );
                return Ok(ExitCode::RuntimeError);
            }
        };

    let finished_at = chrono::Utc::now();
    let total_tests_run = loaded_suite.tests.len();
    let run_report = agentsec_report::RunReport::new(
        run_id,
        project_config.project.name.clone(),
        started_at,
        finished_at,
        vec![resolved_target.id.clone()],
        vec![loaded_suite.id.clone()],
        findings,
        total_tests_run,
    );

    let out_dir = out.unwrap_or(project_config.reports.output_dir);
    let formats = format.unwrap_or(project_config.reports.formats);

    if let Err(e) = agentsec_report::write_reports(&run_report, &formats, Path::new(&out_dir)) {
        eprintln!(
            "{}: Failed to write reports to '{}': {}",
            "Error".red().bold(),
            out_dir,
            e
        );
        return Ok(ExitCode::ReportError);
    }
    println!("Reports generated in '{}' directory.", out_dir.cyan());

    let fail_on_str = fail_on.unwrap_or(project_config.ci.fail_on);
    if !fail_on_str.eq_ignore_ascii_case("never") {
        if let Some(fail_on_severity) = Severity::parse_threshold(&fail_on_str) {
            let exceeded = run_report
                .findings
                .iter()
                .any(|f| !f.suppressed && f.severity >= fail_on_severity);
            if exceeded {
                return Ok(ExitCode::FindingsExceeded);
            }
        }
    }

    Ok(ExitCode::Success)
}

/// Validates a plugin scan-output JSON file against the spec 21.4 shape
/// without invoking any subprocess. This is useful for adapter authors
/// iterating on a plugin binary: they can run their binary's `scan`
/// step by hand, then check the resulting output file is well-formed
/// before wiring it up to `agentsec plugin run`.
fn run_validate_output(path: &str) -> anyhow::Result<ExitCode> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("{}: could not read '{}': {}", "Error".red().bold(), path, e);
            return Ok(ExitCode::RuntimeError);
        }
    };

    match serde_json::from_str::<PluginScanOutput>(&content) {
        Ok(output) => {
            println!(
                "{} '{}' is a valid plugin scan-output file (spec 21.4).",
                "OK:".green().bold(),
                path
            );
            println!("  {}: {}", "plugin".bold(), output.plugin);
            println!("  {}: {}", "version".bold(), output.version);
            println!("  {}: {}", "run_id".bold(), output.run_id);
            println!("  {}: {}", "findings".bold(), output.findings.len());
            Ok(ExitCode::Success)
        }
        Err(e) => {
            eprintln!(
                "{}: '{}' does not match the spec 21.4 plugin scan-output shape: {}",
                "Error".red().bold(),
                path,
                e
            );
            Ok(ExitCode::InvalidConfig)
        }
    }
}
