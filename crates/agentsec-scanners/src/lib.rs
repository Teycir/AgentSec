//! agentsec-scanners: built-in scanners and assertion evaluation.
//!
//! Spec references:
//! - Section 14 (Built-in Scanner Requirements): 14.1 Prompt Injection,
//!   14.2 System Prompt Leakage, 14.3 RAG, 14.4 Agent Tool,
//!   14.5 Output Handling, 14.6 Data Leakage.
//! - Section 15 (Assertion Types) — MVP set only.

pub mod agent_tool;
pub mod assertion_eval;
pub(crate) mod common;
pub mod data_leakage;
pub mod output_handling;
pub mod prompt_injection;
pub mod rag;
pub mod redact;
pub mod response;
pub mod system_prompt_leakage;

pub use agent_tool::AgentToolScanner;
pub use data_leakage::DataLeakageScanner;
pub use output_handling::OutputHandlingScanner;
pub use prompt_injection::PromptInjectionScanner;
pub use rag::RagScanner;
pub use response::TargetResponse;
pub use system_prompt_leakage::SystemPromptLeakageScanner;

use agentsec_config::{Suite, SuiteTest};
use agentsec_core::Finding;

/// Common interface implemented by every built-in scanner.
///
/// A scanner evaluates one `SuiteTest`'s assertions against a captured
/// `TargetResponse` and produces zero or more findings (normally 0 or 1:
/// a failed assertion becomes a finding, per spec section 12/16).
pub trait Scanner {
    /// Machine-readable scanner name, used as `Finding.scanner`.
    fn name(&self) -> &'static str;

    /// Runs every test in `suite` against `response`, returning findings
    /// for any assertion that fails.
    fn run(
        &self,
        run_id: &str,
        target_id: &str,
        suite: &Suite,
        response_for: impl Fn(&SuiteTest) -> TargetResponse,
    ) -> Vec<Finding>;
}
