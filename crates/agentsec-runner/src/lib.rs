//! agentsec-runner: executes suite tests against targets over HTTP and
//! turns failed assertions into findings.

pub mod engine_v2;
pub mod error;
pub mod executor;
pub mod jsonpath;

pub use engine_v2::{run_suite, SuiteRunResult};
pub use error::RunnerError;

/// Builds a `reqwest::Client` with sane defaults for target execution.
pub fn build_http_client(timeout_seconds: u64) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_seconds))
        .build()
}
