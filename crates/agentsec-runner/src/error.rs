use agentsec_core::ExitCode;

/// Errors surfaced while executing a scan run.
///
/// Each variant maps to a stable process exit code (spec section 9) so the
/// CLI can translate failures directly without re-deriving the mapping.
#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    #[error("target \"{target_id}\" is unavailable: {source}")]
    TargetUnavailable {
        target_id: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("target \"{target_id}\" returned an authentication error (HTTP {status})")]
    AuthError { target_id: String, status: u16 },

    #[error("missing required environment variable \"{0}\" for target credentials")]
    MissingEnvVar(String),

    #[error("failed to extract \"{json_path}\" from target \"{target_id}\" response")]
    ResponseExtraction {
        target_id: String,
        json_path: String,
    },

    /// The target responded, but the body could not be parsed as JSON.
    /// Distinct from `ResponseExtraction` (valid JSON, wrong/missing path)
    /// so a malformed or truncated body -- e.g. from a connection drop
    /// mid-response -- isn't silently mistaken for a jsonpath config error.
    #[error("target \"{target_id}\" (HTTP {status}) returned a body that could not be parsed as JSON: {source}; body started with: {body_snippet:?}")]
    ResponseParse {
        target_id: String,
        status: u16,
        body_snippet: String,
        #[source]
        source: serde_json::Error,
    },

    /// A single request/response cycle exceeded an independent deadline
    /// enforced by the runner itself, separate from whatever the
    /// underlying HTTP client's own `.timeout()` is or isn't doing. This
    /// exists as defense-in-depth: if the client-level timeout ever fails
    /// to fire (observed as an indefinite hang against a local Ollama
    /// target with no explanation found in the client code), this still
    /// bounds the call instead of stalling the whole suite run.
    #[error(
        "target \"{target_id}\" did not respond within {timeout_seconds}s (runner-level deadline)"
    )]
    ExecutionTimeout {
        target_id: String,
        timeout_seconds: u64,
    },

    /// The target returned a non-auth error status (429, 5xx, etc.).
    /// Distinct from `AuthError` (401/403) and from `TargetUnavailable`
    /// (the request never got a response at all), so a rate-limited or
    /// overloaded target is distinguishable from both a bad credential
    /// and a dead connection in reports/logs.
    #[error("target \"{target_id}\" returned an error status (HTTP {status})")]
    TargetError { target_id: String, status: u16 },

    #[error("runtime error: {0}")]
    Runtime(#[from] anyhow::Error),
}

impl RunnerError {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            RunnerError::TargetUnavailable { .. } => ExitCode::TargetUnavailable,
            RunnerError::AuthError { .. } => ExitCode::AuthError,
            RunnerError::MissingEnvVar(_) => ExitCode::AuthError,
            RunnerError::ResponseExtraction { .. } => ExitCode::RuntimeError,
            RunnerError::ResponseParse { .. } => ExitCode::RuntimeError,
            RunnerError::ExecutionTimeout { .. } => ExitCode::TargetUnavailable,
            RunnerError::TargetError { .. } => ExitCode::TargetUnavailable,
            RunnerError::Runtime(_) => ExitCode::RuntimeError,
        }
    }
}
