use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A scan target, as declared under `targets:` in `agentsec.yml`.
///
/// Spec section 11: Target Types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub id: String,
    #[serde(flatten)]
    pub kind: TargetKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum TargetKind {
    /// Generic HTTP endpoint. Spec section 11.1.
    HttpChat {
        base_url: String,
        request: HttpRequestSpec,
        response: HttpResponseSpec,
        #[serde(default)]
        capabilities: TargetCapabilities,
    },
    /// OpenAI-compatible `/chat/completions` API. Spec section 11.2.
    OpenaiCompatible {
        base_url: String,
        api_key_env: String,
        model: String,
        #[serde(default)]
        organization_env: Option<String>,
        #[serde(default)]
        default_system_prompt: Option<String>,
        #[serde(default)]
        temperature: Option<f64>,
        #[serde(default)]
        max_tokens: Option<u32>,
    },
    /// Local CLI application. Spec section 11.3.
    Command {
        command: String,
        #[serde(default)]
        working_dir: Option<String>,
        #[serde(default)]
        timeout_seconds: Option<u64>,
    },
    /// Intentionally vulnerable imported lab target. Spec section 11.4.
    Lab { lab_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestSpec {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: serde_json::Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpResponseSpec {
    pub answer_json_path: String,
    #[serde(default)]
    pub citations_json_path: Option<String>,
    #[serde(default)]
    pub tool_calls_json_path: Option<String>,
    #[serde(default)]
    pub trace_id_json_path: Option<String>,
    #[serde(default)]
    pub retrieved_context_json_path: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetCapabilities {
    #[serde(default)]
    pub rag: bool,
    #[serde(default)]
    pub citations: bool,
    #[serde(default)]
    pub retrieved_context_debug: bool,
    #[serde(default)]
    pub tool_calling: bool,
    #[serde(default)]
    pub tool_trace: bool,
}
