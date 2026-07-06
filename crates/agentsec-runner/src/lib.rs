//! agentsec-runner: executes suite tests against targets over HTTP and
//! turns failed assertions into findings.
//!
//! Spec references:
//! - Section 6  (High-level Architecture)
//! - Section 11 (Target Types) — `http-chat` and `openai-compatible` in v0.1
//! - Section 12 (Test Suite Format)

pub mod engine;
pub mod error;
pub mod executor;
pub mod jsonpath;

pub use engine::{run_suite, SuiteRunResult};
pub use error::RunnerError;

/// Builds a `reqwest::Client` with sane defaults for target execution.
///
/// Spec section 23.4 (Network Controls) governs host allowlisting; that
/// check happens at the call site (agentsec-cli) before targets are run,
/// since it needs `ProjectConfig.network` which this crate doesn't depend on.
pub fn build_http_client(timeout_seconds: u64) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_seconds))
        .build()
}
