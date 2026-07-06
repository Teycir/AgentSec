use std::path::Path;

use serde::{Deserialize, Serialize};

use agentsec_core::Severity;

/// A test suite, e.g. `suites/prompt-injection-basic.yml`.
///
/// Spec section 12: Test Suite Format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suite {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub version: String,
    #[serde(default)]
    pub tests: Vec<SuiteTest>,
}

impl Suite {
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read suite {}: {e}", path.display()))?;
        Ok(Self::from_yaml(&text)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteTest {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub category: String,
    #[serde(default)]
    pub owasp: Vec<String>,
    pub input: String,
    #[serde(default)]
    pub assertions: Vec<Assertion>,
    #[serde(default)]
    pub recommendation: String,
}

/// Assertion types checked against a target's response.
///
/// Spec section 15: Assertion Types. Only the MVP set is implemented;
/// the "Future Assertion Types" (llm_judge, embedding_similarity, etc.)
/// are intentionally out of scope for v0.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Assertion {
    Contains { value: String },
    NotContains { value: String },
    RegexMatch { pattern: String },
    RegexNotMatch { pattern: String },
    JsonPathExists { path: String },
    JsonPathNotExists { path: String },
    MaxLength { value: usize },
    MaxLatencyMs { value: u64 },
    ToolNotCalled { tool: String },
    ToolCalled { tool: String },
    CitationsPresent { expected: bool },
    ForbiddenDomainAbsent { domains: Vec<String> },
    SecretNotDetected,
}
