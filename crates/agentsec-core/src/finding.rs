use serde::{Deserialize, Serialize};

use crate::severity::Severity;

/// A single security finding produced by a scanner.
///
/// Spec section 16: Finding Schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub run_id: String,
    pub target_id: String,
    pub suite_id: String,
    pub test_id: String,
    pub scanner: String,
    pub severity: Severity,
    /// Confidence that the observed behavior represents a real finding.
    /// Deterministic findings use 1.0; repeated probabilistic tests use the
    /// observed success rate.
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    pub category: String,
    pub title: String,
    pub description: String,
    #[serde(default)]
    pub owasp: Vec<String>,
    #[serde(default)]
    pub cwe: Vec<String>,
    pub evidence: Evidence,
    pub recommendation: String,
    #[serde(default)]
    pub references: Vec<Reference>,
    #[serde(default)]
    pub suppressed: bool,
    #[serde(default)]
    pub suppression_reason: Option<String>,
}

fn default_confidence() -> f32 {
    1.0
}

impl Finding {
    /// Stable identifier used for baselines/suppressions.
    ///
    /// Spec section 18.2 uses the pattern `target:suite:test`.
    pub fn stable_key(&self) -> String {
        format!("{}:{}:{}", self.target_id, self.suite_id, self.test_id)
    }
}

/// Evidence attached to a finding (request/response summaries, trace info).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub request_summary: String,
    pub response_summary: String,
    #[serde(default)]
    pub raw_request_path: Option<String>,
    #[serde(default)]
    pub raw_response_path: Option<String>,
    #[serde(default)]
    pub trace_id: Option<String>,
    #[serde(default)]
    pub matched_assertion: Option<String>,
    #[serde(default)]
    pub redactions_applied: bool,
}

/// A documentation/reference link attached to a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub title: String,
    pub url: String,
}
