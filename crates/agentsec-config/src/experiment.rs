//! Milestone 1: formal experiment schema and reproducibility manifest.
//!
//! An `Experiment` wraps an existing target/suite pair (already runnable via
//! `agentsec scan`/`agentsec ci`) with reproducibility metadata: a seed,
//! iteration/timeout bounds, and enough identifying info (config hash,
//! agentsec version, timestamps) to produce a manifest that a later
//! `agentsec experiment replay` can compare against.
//!
//! Deliberately thin for M1: no mutation, no attacker. It runs one existing
//! suite through the existing `run_scan_pipeline` and proves the manifest
//! is real and reusable, per the roadmap's Milestone 1 scope.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// An `experiment.yml` document (spec section 5, trimmed to M1's scope).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentSpec {
    pub experiment: ExperimentMeta,
    pub target: String,
    pub suite: String,
    #[serde(default)]
    pub execution: ExecutionSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentMeta {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionSettings {
    #[serde(default)]
    pub seed: Option<u64>,
    #[serde(default = "default_max_iterations")]
    pub max_iterations: u32,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

fn default_max_iterations() -> u32 {
    1
}
fn default_timeout_seconds() -> u64 {
    120
}

impl Default for ExecutionSettings {
    fn default() -> Self {
        Self {
            seed: None,
            max_iterations: default_max_iterations(),
            timeout_seconds: default_timeout_seconds(),
        }
    }
}

impl ExperimentSpec {
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read experiment {}: {e}", path.display()))?;
        Ok(Self::from_yaml(&text)?)
    }
}

/// Reproducibility manifest produced by `agentsec experiment run`, per the
/// roadmap's Milestone 1: seed, target/model identifiers, config hash,
/// agentsec version, and timestamp — enough for `experiment replay` to
/// confirm a later run targeted the same model/suite as the original.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentManifest {
    pub agentsec_version: String,
    pub experiment_id: String,
    pub run_id: String,
    pub seed: Option<u64>,
    pub target_id: String,
    pub target_model: Option<String>,
    pub suite_id: String,
    pub suite_version: String,
    pub config_hash: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// A stable SHA-256 hex digest of the raw experiment YAML text, used as
/// `config_hash` in the manifest. Hashing the raw text (rather than a
/// re-serialized struct) means the hash changes if the file changes in any
/// way a person would notice, including comments/formatting — appropriate
/// for a reproducibility marker where "did the input change at all" matters
/// more than semantic equivalence.
pub fn config_hash(raw_yaml: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_yaml.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_experiment_yaml() {
        let yaml = r#"
experiment:
  id: prompt-injection-evolution-001
target: ollama-gemma4
suite: prompt-injection-basic
execution:
  seed: 42
  max_iterations: 10
  timeout_seconds: 60
"#;
        let spec = ExperimentSpec::from_yaml(yaml).unwrap();
        assert_eq!(spec.experiment.id, "prompt-injection-evolution-001");
        assert_eq!(spec.target, "ollama-gemma4");
        assert_eq!(spec.suite, "prompt-injection-basic");
        assert_eq!(spec.execution.seed, Some(42));
        assert_eq!(spec.execution.max_iterations, 10);
        assert_eq!(spec.execution.timeout_seconds, 60);
    }

    #[test]
    fn execution_settings_default_when_omitted() {
        let yaml = r#"
experiment:
  id: minimal
target: ollama-gemma4
suite: prompt-injection-basic
"#;
        let spec = ExperimentSpec::from_yaml(yaml).unwrap();
        assert_eq!(spec.execution.seed, None);
        assert_eq!(spec.execution.max_iterations, 1);
        assert_eq!(spec.execution.timeout_seconds, 120);
    }

    #[test]
    fn config_hash_is_deterministic_and_sensitive_to_content() {
        let a = config_hash("target: x");
        let b = config_hash("target: x");
        let c = config_hash("target: y");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn config_hash_is_sha256_hex() {
        let hash = config_hash("hello");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
