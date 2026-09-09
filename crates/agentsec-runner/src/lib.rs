//! agentsec-runner: executes suite tests against targets over HTTP and
//! turns failed assertions into findings.

pub mod engine_v2;
pub mod error;
pub mod executor;
pub mod jsonpath;

pub use engine_v2::{run_suite, SuiteRunResult};
pub use error::RunnerError;

/// Builds a `reqwest::Client` with sane defaults for target execution.
///
/// `pool_max_idle_per_host(0)` disables connection reuse: every request
/// opens a fresh TCP connection instead of pulling one from reqwest's
/// idle pool. This is a deliberate trade-off (a bit more per-request
/// overhead) to avoid a suspected failure mode seen against local Ollama
/// targets: a pooled connection that Ollama has already dropped/closed
/// server-side (e.g. after its own keep-alive window, or under load)
/// gets reused by reqwest, and the resulting request fails immediately
/// with a "target unavailable" / connection error rather than a clean
/// timeout. This was not root-caused with connection-level tracing, so
/// treat it as a mitigation to observe, not a confirmed fix.
pub fn build_http_client(timeout_seconds: u64) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_seconds))
        .pool_max_idle_per_host(0)
        .build()
}
