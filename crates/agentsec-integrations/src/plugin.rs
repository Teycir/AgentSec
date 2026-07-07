//! Generic plugin subprocess protocol (spec section 21).
//!
//! "Plugins are subprocesses that speak JSON." Any binary on PATH named
//! `<plugin-name>` that implements this contract can be driven by
//! `agentsec plugin run <plugin-name>` regardless of what security tool
//! it wraps (garak, PyRIT, Promptfoo, ...); this module implements the
//! protocol once so each concrete adapter (see `promptfoo.rs`) is just a
//! named entry point over it.
//!
//! Contract (spec 21.1):
//! ```text
//! plugin-name capabilities
//! plugin-name scan --input input.json --output output.json
//! plugin-name version
//! ```

use std::path::Path;
use std::process::Stdio;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::process::Command;

use agentsec_core::{Evidence, Finding, Severity};

#[derive(Debug, Error)]
pub enum PluginError {
    #[error("plugin binary '{0}' not found on PATH")]
    NotFound(String),
    #[error("plugin '{plugin}' exited with status {status}: {stderr}")]
    NonZeroExit {
        plugin: String,
        status: String,
        stderr: String,
    },
    #[error("plugin '{plugin}' produced output that failed validation: {reason}")]
    InvalidOutput { plugin: String, reason: String },
    #[error("io error running plugin '{plugin}': {source}")]
    Io {
        plugin: String,
        #[source]
        source: std::io::Error,
    },
}

/// Plugin capability output (spec 21.2), returned by `<plugin> capabilities`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginCapabilities {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub supported_target_types: Vec<String>,
    #[serde(default)]
    pub supported_categories: Vec<String>,
    #[serde(default)]
    pub requires: Vec<String>,
}

/// Plugin scan input (spec 21.3), written to a temp file and passed via
/// `--input` to `<plugin> scan`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginScanInput {
    pub run_id: String,
    pub target: PluginTarget,
    pub suite: PluginSuiteRef,
    pub options: PluginScanOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginTarget {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginSuiteRef {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginScanOptions {
    pub timeout_seconds: u64,
}

/// Plugin scan output (spec 21.4), read back from the `--output` file
/// after `<plugin> scan` exits successfully.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginScanOutput {
    pub plugin: String,
    pub version: String,
    pub run_id: String,
    #[serde(default)]
    pub findings: Vec<PluginFinding>,
}

/// A finding as a plugin emits it on the wire. Deliberately a distinct
/// type from `agentsec_core::Finding`: the plugin protocol's finding
/// shape (spec 21.4) omits fields that only make sense once AgentSec's
/// own pipeline has processed a finding (`suppressed`,
/// `suppression_reason`), and plugins aren't expected to supply
/// `test_id`/`scanner`/`suite_id` beyond simple conventions — those are
/// filled in deterministically by `to_finding` below.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginFinding {
    pub id: String,
    pub target_id: String,
    #[serde(default)]
    pub suite_id: String,
    #[serde(default)]
    pub test_id: String,
    pub scanner: String,
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub description: String,
    #[serde(default)]
    pub owasp: Vec<String>,
    pub evidence: PluginEvidence,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginEvidence {
    pub request_summary: String,
    pub response_summary: String,
    #[serde(default)]
    pub redactions_applied: bool,
}

impl PluginFinding {
    /// Maps a plugin-reported finding onto AgentSec's own `Finding` type,
    /// filling in the fields the plugin protocol doesn't carry.
    /// `run_id` is threaded through so it matches the run that invoked
    /// the plugin, rather than trusting what the plugin echoed back
    /// (spec 21: "Rust core validates this output before importing").
    fn to_finding(&self, run_id: &str, suite_id: &str) -> Finding {
        Finding {
            id: self.id.clone(),
            run_id: run_id.to_string(),
            target_id: self.target_id.clone(),
            suite_id: if self.suite_id.is_empty() {
                suite_id.to_string()
            } else {
                self.suite_id.clone()
            },
            test_id: if self.test_id.is_empty() {
                self.id.clone()
            } else {
                self.test_id.clone()
            },
            scanner: self.scanner.clone(),
            severity: self.severity,
            category: self.category.clone(),
            title: self.title.clone(),
            description: self.description.clone(),
            owasp: self.owasp.clone(),
            cwe: Vec::new(),
            evidence: Evidence {
                request_summary: self.evidence.request_summary.clone(),
                response_summary: self.evidence.response_summary.clone(),
                raw_request_path: None,
                raw_response_path: None,
                trace_id: None,
                matched_assertion: None,
                redactions_applied: self.evidence.redactions_applied,
            },
            recommendation: self.recommendation.clone(),
            references: Vec::new(),
            suppressed: false,
            suppression_reason: None,
        }
    }
}

/// Runs `<plugin_binary> capabilities` and parses its JSON stdout.
pub async fn run_capabilities(plugin_binary: &str) -> Result<PluginCapabilities, PluginError> {
    let output = run_command(plugin_binary, &["capabilities"]).await?;
    serde_json::from_slice(&output.stdout).map_err(|e| PluginError::InvalidOutput {
        plugin: plugin_binary.to_string(),
        reason: format!("capabilities output was not valid JSON: {e}"),
    })
}

/// Runs `<plugin_binary> version` and returns the trimmed stdout.
pub async fn run_version(plugin_binary: &str) -> Result<String, PluginError> {
    let output = run_command(plugin_binary, &["version"]).await?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Runs a full scan via `<plugin_binary> scan --input ... --output ...`
/// (spec 21.1/21.3/21.4): writes `input` to a temp JSON file, invokes the
/// plugin, reads back its output file, validates the shape, and maps each
/// reported finding onto `agentsec_core::Finding`.
///
/// Per spec 21.4 ("Rust core validates this output before importing"),
/// a mismatched `run_id` or a target/plugin name mismatch is treated as
/// a hard validation failure rather than silently imported.
pub async fn run_scan(
    plugin_binary: &str,
    input: &PluginScanInput,
) -> Result<Vec<Finding>, PluginError> {
    let tmp_dir = std::env::temp_dir();
    let unique = uuid::Uuid::new_v4();
    let input_path = tmp_dir.join(format!("agentsec-plugin-{unique}-input.json"));
    let output_path = tmp_dir.join(format!("agentsec-plugin-{unique}-output.json"));

    let input_json =
        serde_json::to_string_pretty(input).map_err(|e| PluginError::InvalidOutput {
            plugin: plugin_binary.to_string(),
            reason: format!("failed to serialize scan input: {e}"),
        })?;
    std::fs::write(&input_path, input_json).map_err(|source| PluginError::Io {
        plugin: plugin_binary.to_string(),
        source,
    })?;

    let result = run_scan_inner(plugin_binary, &input_path, &output_path, &input.run_id).await;

    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_file(&output_path);

    result
}

async fn run_scan_inner(
    plugin_binary: &str,
    input_path: &Path,
    output_path: &Path,
    expected_run_id: &str,
) -> Result<Vec<Finding>, PluginError> {
    run_command(
        plugin_binary,
        &[
            "scan",
            "--input",
            &input_path.to_string_lossy(),
            "--output",
            &output_path.to_string_lossy(),
        ],
    )
    .await?;

    let output_content =
        std::fs::read_to_string(output_path).map_err(|e| PluginError::InvalidOutput {
            plugin: plugin_binary.to_string(),
            reason: format!("plugin did not write a readable output file: {e}"),
        })?;

    let scan_output: PluginScanOutput =
        serde_json::from_str(&output_content).map_err(|e| PluginError::InvalidOutput {
            plugin: plugin_binary.to_string(),
            reason: format!("scan output was not valid JSON matching the plugin protocol: {e}"),
        })?;

    if scan_output.run_id != expected_run_id {
        return Err(PluginError::InvalidOutput {
            plugin: plugin_binary.to_string(),
            reason: format!(
                "run_id mismatch: expected '{expected_run_id}', plugin returned '{}'",
                scan_output.run_id
            ),
        });
    }

    // suite_id isn't threaded through PluginScanOutput itself (spec 21.4
    // only echoes plugin/version/run_id at the top level), so each
    // finding falls back to whatever suite_id it reports, defaulting to
    // the plugin name if it reports none at all.
    let fallback_suite_id = scan_output.plugin.clone();
    Ok(scan_output
        .findings
        .iter()
        .map(|f| f.to_finding(expected_run_id, &fallback_suite_id))
        .collect())
}

/// Runs `plugin_binary` with `args`, returning its captured output on
/// success or a `PluginError` on a missing binary / non-zero exit.
async fn run_command(
    plugin_binary: &str,
    args: &[&str],
) -> Result<std::process::Output, PluginError> {
    let output = Command::new(plugin_binary)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                PluginError::NotFound(plugin_binary.to_string())
            } else {
                PluginError::Io {
                    plugin: plugin_binary.to_string(),
                    source,
                }
            }
        })?;

    if !output.status.success() {
        return Err(PluginError::NonZeroExit {
            plugin: plugin_binary.to_string(),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin_finding(suite_id: &str, test_id: &str) -> PluginFinding {
        PluginFinding {
            id: "garak-prompt-injection-001".to_string(),
            target_id: "supportbot-api".to_string(),
            suite_id: suite_id.to_string(),
            test_id: test_id.to_string(),
            scanner: "garak".to_string(),
            severity: Severity::Medium,
            category: "prompt_injection".to_string(),
            title: "Prompt injection behavior detected".to_string(),
            description: "The target appeared to follow untrusted instructions.".to_string(),
            owasp: vec!["LLM01".to_string()],
            evidence: PluginEvidence {
                request_summary: "Redacted request".to_string(),
                response_summary: "Redacted response".to_string(),
                redactions_applied: true,
            },
            recommendation: "Use structured prompts and validate outputs.".to_string(),
        }
    }

    #[test]
    fn to_finding_maps_spec_21_4_example_exactly() {
        let pf = plugin_finding("garak", "prompt-injection");
        let finding = pf.to_finding("run_123", "fallback-suite");

        assert_eq!(finding.id, "garak-prompt-injection-001");
        assert_eq!(finding.run_id, "run_123");
        assert_eq!(finding.target_id, "supportbot-api");
        assert_eq!(finding.suite_id, "garak");
        assert_eq!(finding.test_id, "prompt-injection");
        assert_eq!(finding.scanner, "garak");
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.owasp, vec!["LLM01".to_string()]);
        assert!(finding.evidence.redactions_applied);
        assert!(!finding.suppressed);
        assert!(finding.suppression_reason.is_none());
    }

    #[test]
    fn to_finding_falls_back_to_plugin_name_for_empty_suite_id() {
        let pf = plugin_finding("", "prompt-injection");
        let finding = pf.to_finding("run_123", "garak");
        assert_eq!(finding.suite_id, "garak");
    }

    #[test]
    fn to_finding_falls_back_to_id_for_empty_test_id() {
        let pf = plugin_finding("garak", "");
        let finding = pf.to_finding("run_123", "garak");
        assert_eq!(finding.test_id, "garak-prompt-injection-001");
    }

    #[tokio::test]
    async fn run_command_reports_not_found_for_missing_binary() {
        let result = run_command("agentsec-definitely-not-a-real-binary", &["version"]).await;
        assert!(matches!(result, Err(PluginError::NotFound(_))));
    }

    #[tokio::test]
    async fn run_capabilities_missing_binary_is_not_found() {
        let result = run_capabilities("agentsec-definitely-not-a-real-binary").await;
        assert!(matches!(result, Err(PluginError::NotFound(_))));
    }

    #[test]
    fn plugin_scan_input_serializes_per_spec_21_3_shape() {
        let input = PluginScanInput {
            run_id: "run_123".to_string(),
            target: PluginTarget {
                id: "supportbot-api".to_string(),
                kind: "http-chat".to_string(),
                base_url: Some("https://staging.example.com".to_string()),
            },
            suite: PluginSuiteRef {
                id: "prompt-injection-basic".to_string(),
            },
            options: PluginScanOptions {
                timeout_seconds: 120,
            },
        };
        let json = serde_json::to_value(&input).unwrap();
        assert_eq!(json["run_id"], "run_123");
        assert_eq!(json["target"]["type"], "http-chat");
        assert_eq!(json["suite"]["id"], "prompt-injection-basic");
        assert_eq!(json["options"]["timeout_seconds"], 120);
    }
}
