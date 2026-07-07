//! The shared scan pipeline used by both `agentsec ci` and `agentsec scan`:
//! network policy check -> load suppressions/baseline -> run suites ->
//! redact + suppress findings -> write reports -> update baseline ->
//! evaluate fail_on severity -> print summary.

use std::collections::HashSet;
use std::path::Path;

use owo_colors::{OwoColorize, Style};
use serde::{Deserialize, Serialize};

use agentsec_config::{ProjectConfig, Suite, Target};
use agentsec_core::{ExitCode, Finding, Severity};
use agentsec_report::RunReport;

use crate::network_policy::is_host_private;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionItem {
    pub finding_id: String,
    pub reason: String,
    pub expires: Option<String>,
    pub approved_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionsConfig {
    #[serde(default)]
    pub suppressions: Vec<SuppressionItem>,
}

/// Options controlling one pipeline run. Grouped into a struct (rather than
/// passed as loose positional args) because most callers only care about
/// overriding one or two of these; a struct makes each call site self-
/// documenting.
pub struct PipelineOptions {
    pub out_dir_opt: Option<String>,
    pub formats_opt: Option<Vec<String>>,
    pub fail_on_opt: Option<String>,
    pub baseline_opt: Option<String>,
    pub update_baseline: bool,
    pub timeout_override: Option<u64>,
}

/// Builds the stable `target:suite:test` lookup key used by both baseline
/// matching and suppression matching. Mirrors `Finding::stable_key()`
/// exactly; kept as a free function here (rather than only calling the
/// method) so baseline entries — which are loaded from a JSON `RunReport`,
/// not from live `Finding` values — can be keyed the same way.
pub fn stable_key(target_id: &str, suite_id: &str, test_id: &str) -> String {
    format!("{target_id}:{suite_id}:{test_id}")
}

/// Loads baseline finding keys from a previously-written `RunReport` JSON
/// file at `path`. Returns an empty set if the file doesn't exist or fails
/// to parse (a missing/corrupt baseline is treated as "no baseline" rather
/// than a hard error, since baselines are an opt-in convenience).
pub fn load_baseline_keys(path: &Path) -> HashSet<String> {
    let mut keys = HashSet::new();
    if !path.exists() {
        return keys;
    }
    let Ok(content) = std::fs::read_to_string(path) else {
        return keys;
    };
    if let Ok(report) = serde_json::from_str::<RunReport>(&content) {
        for finding in &report.findings {
            keys.insert(stable_key(
                &finding.target_id,
                &finding.suite_id,
                &finding.test_id,
            ));
        }
    }
    keys
}

/// Result of checking one suppression entry against "today".
#[derive(Debug, PartialEq, Eq)]
pub enum SuppressionCheck {
    /// No suppression entry matched this finding at all.
    NoMatch,
    /// A matching entry was found and is still in effect.
    Active { reason: String },
    /// A matching entry was found but its `expires` date has passed.
    Expired { expires: String },
}

/// Checks `unique_key` against the suppression list, applying expiry.
/// `today` is passed in explicitly (rather than calling `Utc::now()`
/// internally) so this is deterministic and unit-testable.
pub fn check_suppression(
    items: &[SuppressionItem],
    unique_key: &str,
    today: chrono::NaiveDate,
) -> SuppressionCheck {
    let Some(item) = items.iter().find(|s| s.finding_id == unique_key) else {
        return SuppressionCheck::NoMatch;
    };

    if let Some(expiry_str) = &item.expires {
        if let Ok(expiry_date) = chrono::NaiveDate::parse_from_str(expiry_str, "%Y-%m-%d") {
            if today > expiry_date {
                return SuppressionCheck::Expired {
                    expires: expiry_str.clone(),
                };
            }
        }
    }

    SuppressionCheck::Active {
        reason: item.reason.clone(),
    }
}

pub async fn run_scan_pipeline(
    config: ProjectConfig,
    targets: Vec<Target>,
    suites: Vec<Suite>,
    options: PipelineOptions,
) -> anyhow::Result<ExitCode> {
    let PipelineOptions {
        out_dir_opt,
        formats_opt,
        fail_on_opt,
        baseline_opt,
        update_baseline,
        timeout_override,
    } = options;

    // 1. Network policy controls
    for target in &targets {
        let base_url = match &target.kind {
            agentsec_config::target::TargetKind::HttpChat { base_url, .. } => base_url.as_str(),
            agentsec_config::target::TargetKind::OpenaiCompatible { base_url, .. } => {
                base_url.as_str()
            }
            _ => "",
        };

        if let Ok(url) = url::Url::parse(base_url) {
            if let Some(host) = url.host_str() {
                if !config.network.allowed_hosts.is_empty()
                    && !config.network.allowed_hosts.contains(&host.to_string())
                {
                    eprintln!(
                        "{}: Target host '{}' is not in network allowed_hosts allowlist.",
                        "Error".red().bold(),
                        host
                    );
                    return Ok(ExitCode::NetworkViolation);
                }
                if config.network.deny_private_networks && is_host_private(host).await {
                    eprintln!("{}: Target host '{}' resolves to a private network address which is denied.", "Error".red().bold(), host);
                    return Ok(ExitCode::NetworkViolation);
                }
            }
        }
    }

    // 2. Load Suppressions
    let suppressions_path = config
        .suppressions
        .as_ref()
        .map(|s| Path::new(&s.file))
        .unwrap_or_else(|| Path::new(".agentsec/suppressions.yml"));
    let suppression_items = if suppressions_path.exists() {
        let content = std::fs::read_to_string(suppressions_path)?;
        match serde_yaml::from_str::<SuppressionsConfig>(&content) {
            Ok(parsed) => parsed.suppressions,
            Err(e) => {
                eprintln!(
                    "{}: failed to parse suppressions file '{}': {}",
                    "Warning".yellow().bold(),
                    suppressions_path.display(),
                    e
                );
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    // 3. Load Baseline
    let baseline_path = baseline_opt
        .as_ref()
        .map(Path::new)
        .or_else(|| config.baseline.as_ref().map(|b| Path::new(&b.file)));
    let baseline_keys = baseline_path.map(load_baseline_keys).unwrap_or_default();

    // 4. Run Execution
    let run_id = uuid::Uuid::new_v4().to_string();
    let started_at = chrono::Utc::now();
    let timeout = timeout_override.unwrap_or(config.ci.timeout_seconds);
    let client = agentsec_runner::build_http_client(timeout)?;

    let mut all_findings = Vec::new();
    let mut total_tests_run = 0;
    let mut target_ids = Vec::new();
    let mut suite_ids = Vec::new();

    for target in &targets {
        target_ids.push(target.id.clone());
        for suite in &suites {
            if !suite_ids.contains(&suite.id) {
                suite_ids.push(suite.id.clone());
            }
            total_tests_run += suite.tests.len();

            println!(
                "Running suite {} against target {}...",
                suite.name.cyan(),
                target.id.yellow()
            );
            match agentsec_runner::run_suite(
                &client,
                &run_id,
                target,
                suite,
                config.limits.as_ref(),
                config.policies.as_ref(),
            )
            .await
            {
                Ok(res) => {
                    for (test_id, err_msg) in res.errors {
                        // Runtime/HTTP errors (e.g. reqwest failures) can embed the
                        // full request URL, including query strings or an API key
                        // placed in the URL rather than a header. Redact before
                        // printing, mirroring the redaction applied to findings below.
                        let safe_err_msg = if config.redaction.enabled {
                            agentsec_scanners::data_leakage::redact_secrets_in_text(&err_msg)
                        } else {
                            err_msg
                        };
                        eprintln!(
                            "{}: test '{}' failed to execute: {}",
                            "Error".red().bold(),
                            test_id,
                            safe_err_msg
                        );
                    }
                    all_findings.extend(res.findings);
                }
                Err(e) => {
                    eprintln!("{}: Failed to execute suite: {}", "Error".red().bold(), e);
                    let code = match e {
                        agentsec_runner::RunnerError::TargetUnavailable { .. } => {
                            ExitCode::TargetUnavailable
                        }
                        agentsec_runner::RunnerError::AuthError { .. } => ExitCode::AuthError,
                        agentsec_runner::RunnerError::MissingEnvVar(_) => ExitCode::InvalidConfig,
                        _ => ExitCode::RuntimeError,
                    };
                    return Ok(code);
                }
            }
        }
    }

    // 5. Post-Process Findings (Redaction + Suppressions)
    let today = chrono::Utc::now().date_naive();
    for finding in &mut all_findings {
        let unique_key = stable_key(&finding.target_id, &finding.suite_id, &finding.test_id);

        if config.redaction.enabled {
            finding.description =
                agentsec_scanners::data_leakage::redact_secrets_in_text(&finding.description);
            finding.evidence.response_summary =
                agentsec_scanners::data_leakage::redact_secrets_in_text(
                    &finding.evidence.response_summary,
                );
            finding.evidence.request_summary =
                agentsec_scanners::data_leakage::redact_secrets_in_text(
                    &finding.evidence.request_summary,
                );
            if let Some(matched) = &mut finding.evidence.matched_assertion {
                *matched = agentsec_scanners::data_leakage::redact_secrets_in_text(matched);
            }
            finding.evidence.redactions_applied = true;
        }

        match check_suppression(&suppression_items, &unique_key, today) {
            SuppressionCheck::Active { reason } => {
                finding.suppressed = true;
                finding.suppression_reason = Some(reason);
            }
            SuppressionCheck::Expired { expires } => {
                if config.ci.fail_on_expired_suppressions {
                    eprintln!(
                        "{}: Suppression for '{}' has expired on {}!",
                        "Warning".yellow().bold(),
                        unique_key,
                        expires
                    );
                }
            }
            SuppressionCheck::NoMatch => {}
        }
    }

    // 6. Write Reports
    let finished_at = chrono::Utc::now();
    let run_report = RunReport::new(
        run_id.clone(),
        config.project.name.clone(),
        started_at,
        finished_at,
        target_ids,
        suite_ids,
        all_findings.clone(),
        total_tests_run,
    );

    let out_dir = out_dir_opt.unwrap_or(config.reports.output_dir);
    let formats = formats_opt.unwrap_or(config.reports.formats);

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

    // 7. Update Baseline if requested
    if update_baseline {
        if let Some(path) = baseline_path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let report_json = serde_json::to_string_pretty(&run_report)?;
            std::fs::write(path, report_json)?;
            println!("Baseline updated at '{}'.", path.display().cyan());
        } else {
            eprintln!(
                "{}: Baseline update requested, but no baseline file configured or specified.",
                "Warning".yellow().bold()
            );
        }
    }

    // 8. Build Severity Evaluation
    let fail_on_str = fail_on_opt.unwrap_or(config.ci.fail_on);
    let mut findings_exceeded = false;

    if !fail_on_str.eq_ignore_ascii_case("never") {
        if let Some(fail_on_severity) = Severity::parse_threshold(&fail_on_str) {
            for finding in &run_report.findings {
                let unique_key =
                    stable_key(&finding.target_id, &finding.suite_id, &finding.test_id);
                let is_baseline = baseline_keys.contains(&unique_key);

                if !finding.suppressed && !is_baseline && finding.severity >= fail_on_severity {
                    findings_exceeded = true;
                }
            }
        }
    }

    // 9. Display Terminal Summary
    print_terminal_summary(&run_report, &baseline_keys);

    if findings_exceeded {
        Ok(ExitCode::FindingsExceeded)
    } else {
        Ok(ExitCode::Success)
    }
}

fn print_terminal_summary(report: &RunReport, baseline_keys: &HashSet<String>) {
    println!(
        "\n{}",
        "==================================================".green()
    );
    println!("             AGENTSEC LAB RUN SUMMARY");
    println!(
        "{}",
        "==================================================".green()
    );
    println!("Project:       {}", report.project_name.bold());
    println!("Run ID:        {}", report.run_id);
    println!(
        "Duration:      {} ms",
        (report.finished_at - report.started_at).num_milliseconds()
    );
    println!("Total Tests:   {}", report.summary.total_tests_run);
    println!("Total Findings:{}", report.summary.total_findings);
    println!("--------------------------------------------------");

    println!("Severity counts:");
    for sev in &Severity::ALL {
        let count = report
            .findings
            .iter()
            .filter(|f| f.severity == *sev && !f.suppressed)
            .count();
        let style = match sev {
            Severity::Critical => Style::new().magenta().bold(),
            Severity::High => Style::new().red().bold(),
            Severity::Medium => Style::new().yellow().bold(),
            Severity::Low => Style::new().blue(),
            Severity::Info => Style::new(),
        };
        println!("  {: <10} {}", sev.to_string().style(style), count);
    }
    println!("--------------------------------------------------");

    let unsuppressed_active_findings: Vec<&Finding> =
        report.findings.iter().filter(|f| !f.suppressed).collect();

    if unsuppressed_active_findings.is_empty() {
        println!("{}", "No active findings found. Great job!".green().bold());
    } else {
        println!("{}", "Active Findings:".red().bold());
        for finding in unsuppressed_active_findings {
            let unique_key = stable_key(&finding.target_id, &finding.suite_id, &finding.test_id);
            let is_baseline = baseline_keys.contains(&unique_key);

            let style = match finding.severity {
                Severity::Critical => Style::new().magenta().bold(),
                Severity::High => Style::new().red().bold(),
                Severity::Medium => Style::new().yellow().bold(),
                Severity::Low => Style::new().blue(),
                Severity::Info => Style::new(),
            };

            let baseline_tag = if is_baseline {
                " (baseline)".style(Style::new().dimmed()).to_string()
            } else {
                "".to_string()
            };
            println!(
                "\n{} {}:{}{} {}",
                format!("[{}]", finding.severity).style(style),
                finding.suite_id.cyan(),
                finding.test_id.yellow(),
                baseline_tag,
                finding.title.bold()
            );
            println!("  Description:    {}", finding.description);
            println!("  Recommendation: {}", finding.recommendation);
        }
    }

    let suppressed_findings: Vec<&Finding> =
        report.findings.iter().filter(|f| f.suppressed).collect();

    if !suppressed_findings.is_empty() {
        println!("\n{}", "Suppressed Findings:".blue().bold());
        for finding in suppressed_findings {
            println!(
                "  [{}] {}:{} ({})",
                finding.severity,
                finding.suite_id.cyan(),
                finding.test_id.yellow(),
                finding
                    .suppression_reason
                    .as_deref()
                    .unwrap_or("no reason given")
                    .dimmed()
            );
        }
    }
    println!(
        "{}",
        "==================================================".green()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(finding_id: &str, expires: Option<&str>) -> SuppressionItem {
        SuppressionItem {
            finding_id: finding_id.to_string(),
            reason: "test reason".to_string(),
            expires: expires.map(|s| s.to_string()),
            approved_by: None,
        }
    }

    fn date(s: &str) -> chrono::NaiveDate {
        chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn stable_key_matches_finding_stable_key_format() {
        assert_eq!(stable_key("t", "s", "test"), "t:s:test");
    }

    #[test]
    fn check_suppression_no_match_when_id_absent() {
        let items = vec![item("other:suite:test", None)];
        assert_eq!(
            check_suppression(&items, "t:s:test", date("2026-01-01")),
            SuppressionCheck::NoMatch
        );
    }

    #[test]
    fn check_suppression_active_with_no_expiry() {
        let items = vec![item("t:s:test", None)];
        assert_eq!(
            check_suppression(&items, "t:s:test", date("2026-01-01")),
            SuppressionCheck::Active {
                reason: "test reason".to_string()
            }
        );
    }

    #[test]
    fn check_suppression_active_before_expiry() {
        let items = vec![item("t:s:test", Some("2026-12-31"))];
        assert_eq!(
            check_suppression(&items, "t:s:test", date("2026-01-01")),
            SuppressionCheck::Active {
                reason: "test reason".to_string()
            }
        );
    }

    #[test]
    fn check_suppression_expired_after_expiry() {
        let items = vec![item("t:s:test", Some("2026-01-01"))];
        assert_eq!(
            check_suppression(&items, "t:s:test", date("2026-06-01")),
            SuppressionCheck::Expired {
                expires: "2026-01-01".to_string()
            }
        );
    }

    #[test]
    fn check_suppression_active_on_expiry_day_itself() {
        // today == expires is NOT expired: the check is `today > expiry_date`.
        let items = vec![item("t:s:test", Some("2026-06-01"))];
        assert_eq!(
            check_suppression(&items, "t:s:test", date("2026-06-01")),
            SuppressionCheck::Active {
                reason: "test reason".to_string()
            }
        );
    }

    #[test]
    fn check_suppression_malformed_expiry_treated_as_active() {
        // An unparsable expiry date silently falls through to "active"
        // (matches the original main.rs behavior: `if let Ok(...)` guard).
        let items = vec![item("t:s:test", Some("not-a-date"))];
        assert_eq!(
            check_suppression(&items, "t:s:test", date("2026-06-01")),
            SuppressionCheck::Active {
                reason: "test reason".to_string()
            }
        );
    }

    #[test]
    fn load_baseline_keys_missing_file_returns_empty() {
        let keys = load_baseline_keys(Path::new("/nonexistent/path/baseline.json"));
        assert!(keys.is_empty());
    }
}
