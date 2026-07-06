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
            RunnerError::Runtime(_) => ExitCode::RuntimeError,
        }
    }
}
