use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::target::Target;

/// Top-level `agentsec.yml` project configuration.
///
/// Spec section 10: Configuration File.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub version: String,
    pub project: ProjectMeta,
    #[serde(default)]
    pub targets: Vec<Target>,
    #[serde(default)]
    pub suites: Vec<String>,
    #[serde(default)]
    pub ci: CiSettings,
    #[serde(default)]
    pub reports: ReportSettings,
    #[serde(default)]
    pub redaction: RedactionSettings,
    #[serde(default)]
    pub network: NetworkSettings,
    #[serde(default)]
    pub evidence: EvidenceSettings,
    #[serde(default)]
    pub safety: SafetySettings,
    #[serde(default)]
    pub suppressions: Option<SuppressionsFile>,
    #[serde(default)]
    pub baseline: Option<BaselineFile>,
    #[serde(default)]
    pub telemetry: TelemetrySettings,
    #[serde(default)]
    pub policies: Option<Policies>,
    #[serde(default)]
    pub limits: Option<LimitsSettings>,
}

impl ProjectConfig {
    /// Parses a project config from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    /// Loads and parses a project config from disk.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config {}: {e}", path.display()))?;
        Ok(Self::from_yaml(&text)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMeta {
    pub name: String,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiSettings {
    #[serde(default = "default_fail_on")]
    pub fail_on: String,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_concurrency")]
    pub concurrency: u32,
    #[serde(default)]
    pub fail_on_expired_suppressions: bool,
}

fn default_fail_on() -> String {
    "high".to_string()
}
fn default_timeout() -> u64 {
    120
}
fn default_concurrency() -> u32 {
    4
}

impl Default for CiSettings {
    fn default() -> Self {
        Self {
            fail_on: default_fail_on(),
            timeout_seconds: default_timeout(),
            concurrency: default_concurrency(),
            fail_on_expired_suppressions: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSettings {
    #[serde(default = "default_formats")]
    pub formats: Vec<String>,
    #[serde(default = "default_output_dir")]
    pub output_dir: String,
}

fn default_formats() -> Vec<String> {
    vec!["json".to_string(), "markdown".to_string()]
}
fn default_output_dir() -> String {
    "reports/agentsec".to_string()
}

impl Default for ReportSettings {
    fn default() -> Self {
        Self {
            formats: default_formats(),
            output_dir: default_output_dir(),
        }
    }
}

/// Spec section 23.1: Secret Handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionSettings {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_redacted_headers")]
    pub headers: Vec<String>,
    #[serde(default)]
    pub json_paths: Vec<String>,
}

fn default_true() -> bool {
    true
}
fn default_redacted_headers() -> Vec<String> {
    vec![
        "Authorization".to_string(),
        "Cookie".to_string(),
        "X-API-Key".to_string(),
    ]
}

impl Default for RedactionSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            headers: default_redacted_headers(),
            json_paths: Vec::new(),
        }
    }
}

/// Spec section 23.4: Network Controls.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkSettings {
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub deny_private_networks: bool,
}

/// Spec section 23.3: Data Retention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSettings {
    #[serde(default)]
    pub store_raw_requests: bool,
    #[serde(default = "default_true")]
    pub store_raw_responses: bool,
    #[serde(default = "default_true")]
    pub redact: bool,
}

impl Default for EvidenceSettings {
    fn default() -> Self {
        Self {
            store_raw_requests: false,
            store_raw_responses: true,
            redact: true,
        }
    }
}

/// Spec section 23.5: Destructive Testing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SafetySettings {
    #[serde(default)]
    pub destructive_tests: bool,
}

/// Spec section 23.2: No Telemetry by Default.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TelemetrySettings {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionsFile {
    pub file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineFile {
    pub file: String,
}

/// Spec section 10.4: Agent / Tool-calling Config policies.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policies {
    #[serde(default)]
    pub tool_calls: Option<ToolCallPolicy>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolCallPolicy {
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub forbidden_tools: Vec<String>,
    #[serde(default)]
    pub require_human_approval: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LimitsSettings {
    #[serde(default)]
    pub max_tokens_per_session: Option<usize>,
    #[serde(default)]
    pub max_latency_per_request_ms: Option<u64>,
}
