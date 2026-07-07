//! Promptfoo adapter (spec section 21, scoped to the first named
//! integration per the roadmap: "scope to just Promptfoo first — it's
//! YAML-config-driven like AgentSec itself").
//!
//! This is a thin named entry point over the generic `plugin` protocol
//! module. It does not embed any Promptfoo-specific parsing logic itself
//! — per spec 21, the plugin binary (conventionally named `promptfoo` on
//! PATH, see `agentsec plugin run promptfoo`) is responsible for shelling
//! out to Promptfoo and translating its own JSON output into the plugin
//! scan-output shape (spec 21.4); this module's job is only to build a
//! well-formed scan input, invoke that binary, and validate/import
//! whatever it returns.

use agentsec_config::{Suite, Target, TargetKind};
use agentsec_core::Finding;

use crate::plugin::{
    self, PluginCapabilities, PluginError, PluginScanInput, PluginScanOptions, PluginSuiteRef,
    PluginTarget,
};

/// The binary name looked up on PATH for the Promptfoo plugin adapter,
/// per the `agentsec plugin run <name>` convention (spec 8.8).
pub const BINARY_NAME: &str = "promptfoo";

/// Returns the Promptfoo plugin's advertised capabilities (spec 21.2),
/// or an error if the `promptfoo` binary isn't on PATH or doesn't speak
/// the protocol.
pub async fn capabilities() -> Result<PluginCapabilities, PluginError> {
    plugin::run_capabilities(BINARY_NAME).await
}

/// Runs `suite` against `target` through the Promptfoo plugin adapter and
/// returns the imported, validated findings.
///
/// `run_id` should be the same run id used for any native scanners in the
/// same `agentsec` invocation, so plugin-sourced and native findings share
/// one `RunReport`.
pub async fn run_scan(
    run_id: &str,
    target: &Target,
    suite: &Suite,
    timeout_seconds: u64,
) -> Result<Vec<Finding>, PluginError> {
    let input = PluginScanInput {
        run_id: run_id.to_string(),
        target: PluginTarget {
            id: target.id.clone(),
            kind: target_type_str(&target.kind).to_string(),
            base_url: target_base_url(&target.kind),
        },
        suite: PluginSuiteRef {
            id: suite.id.clone(),
        },
        options: PluginScanOptions { timeout_seconds },
    };

    plugin::run_scan(BINARY_NAME, &input).await
}

fn target_type_str(kind: &TargetKind) -> &'static str {
    match kind {
        TargetKind::HttpChat { .. } => "http-chat",
        TargetKind::OpenaiCompatible { .. } => "openai-compatible",
        TargetKind::Command { .. } => "command",
        TargetKind::Lab { .. } => "lab",
    }
}

fn target_base_url(kind: &TargetKind) -> Option<String> {
    match kind {
        TargetKind::HttpChat { base_url, .. } => Some(base_url.clone()),
        TargetKind::OpenaiCompatible { base_url, .. } => Some(base_url.clone()),
        TargetKind::Command { .. } | TargetKind::Lab { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsec_config::target::{HttpRequestSpec, HttpResponseSpec, TargetCapabilities};

    fn http_chat_target() -> Target {
        Target {
            id: "supportbot-api".to_string(),
            kind: TargetKind::HttpChat {
                base_url: "https://staging.example.com".to_string(),
                request: HttpRequestSpec {
                    method: "POST".to_string(),
                    path: "/chat".to_string(),
                    headers: Default::default(),
                    body: serde_json::json!({}),
                },
                response: HttpResponseSpec::default(),
                capabilities: TargetCapabilities::default(),
            },
        }
    }

    fn lab_target() -> Target {
        Target {
            id: "rag-poisoning-poc".to_string(),
            kind: TargetKind::Lab {
                lab_id: "rag-poisoning-poc".to_string(),
            },
        }
    }

    #[test]
    fn target_type_str_matches_spec_21_3_vocabulary() {
        assert_eq!(target_type_str(&http_chat_target().kind), "http-chat");
        assert_eq!(target_type_str(&lab_target().kind), "lab");
    }

    #[test]
    fn base_url_present_for_http_chat_absent_for_lab() {
        assert_eq!(
            target_base_url(&http_chat_target().kind),
            Some("https://staging.example.com".to_string())
        );
        assert_eq!(target_base_url(&lab_target().kind), None);
    }

    #[tokio::test]
    async fn run_scan_reports_not_found_when_promptfoo_binary_absent() {
        // In this test environment there is no `promptfoo` binary on
        // PATH, so this exercises the real not-found path end to end
        // (rather than a real Promptfoo installation, which CI can't
        // assume is present).
        let target = http_chat_target();
        let suite = Suite {
            id: "prompt-injection-basic".to_string(),
            name: "Prompt Injection Basic".to_string(),
            description: String::new(),
            version: "1".to_string(),
            tests: Vec::new(),
        };
        let result = run_scan("run_123", &target, &suite, 120).await;
        assert!(matches!(result, Err(PluginError::NotFound(_))));
    }
}
