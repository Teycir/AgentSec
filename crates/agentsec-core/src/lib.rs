//! agentsec-core: shared domain types used across the AgentSec Lab workspace.
//!
//! Spec references:
//! - Section 9  (Exit Codes)
//! - Section 16 (Finding Schema)
//! - Section 24 (OWASP Mapping)

pub mod exit_code;
pub mod finding;
pub mod owasp;
pub mod severity;

pub use exit_code::ExitCode;
pub use finding::{Evidence, Finding, Reference};
pub use severity::Severity;
