//! agentsec-config: `agentsec.yml` project config and suite (`*.yml`) parsing.
//!
//! Spec references:
//! - Section 10 (Configuration File)
//! - Section 11 (Target Types)
//! - Section 12 (Test Suite Format)
//! - Section 8.3 (agentsec validate)

pub mod project;
pub mod suite;
pub mod target;
pub mod validate;

pub use project::ProjectConfig;
pub use suite::{Assertion, Suite, SuiteTest};
pub use target::Target;
pub use validate::{validate_config, validate_suite, validate_suite_ids, ValidationError};
