use thiserror::Error;

use crate::project::ProjectConfig;
use crate::suite::Suite;

/// Errors surfaced by `agentsec validate`.
///
/// Spec section 8.3 lists the checks this module should perform; the MVP
/// implements the structural/referential subset (YAML syntax is already
/// enforced by serde_yaml at parse time).
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("config has no targets defined")]
    NoTargets,
    #[error("config references unknown suite id: {0}")]
    UnknownSuiteId(String),
    #[error("invalid severity threshold in ci.fail_on: {0}")]
    InvalidSeverityThreshold(String),
    #[error("invalid report format: {0}")]
    InvalidReportFormat(String),
    #[error("duplicate target id: {0}")]
    DuplicateTargetId(String),
    #[error("target {target} references environment variable {var} which is not set")]
    MissingEnvVar { target: String, var: String },
}

const VALID_FORMATS: &[&str] = &["json", "sarif", "junit", "markdown", "html"];

/// Validates a loaded `ProjectConfig` against the checks in spec 8.3 that
/// don't require loading external suite files (see `validate_suite_ids`
/// for the suite cross-reference check).
pub fn validate_config(config: &ProjectConfig) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    if config.targets.is_empty() {
        errors.push(ValidationError::NoTargets);
    }

    let mut seen_ids = std::collections::HashSet::new();
    for target in &config.targets {
        if !seen_ids.insert(target.id.clone()) {
            errors.push(ValidationError::DuplicateTargetId(target.id.clone()));
        }
    }

    if agentsec_core::Severity::parse_threshold(&config.ci.fail_on).is_none() {
        errors.push(ValidationError::InvalidSeverityThreshold(
            config.ci.fail_on.clone(),
        ));
    }

    for fmt in &config.reports.formats {
        if !VALID_FORMATS.contains(&fmt.as_str()) {
            errors.push(ValidationError::InvalidReportFormat(fmt.clone()));
        }
    }

    errors
}

/// Cross-references `config.suites` against the set of suite IDs actually
/// available on disk (spec 8.3: "Unknown suite IDs").
pub fn validate_suite_ids(
    config: &ProjectConfig,
    known_suite_ids: &[String],
) -> Vec<ValidationError> {
    config
        .suites
        .iter()
        .filter(|id| !known_suite_ids.contains(id))
        .map(|id| ValidationError::UnknownSuiteId(id.clone()))
        .collect()
}

/// Validates an individual suite file's structural integrity.
///
/// Spec 8.3: "Unknown assertion types" is enforced at parse time via serde's
/// tagged enum (unrecognized `type:` values fail to deserialize), so this
/// function focuses on checks that survive successful parsing.
pub fn validate_suite(suite: &Suite) -> Vec<ValidationError> {
    // MVP: structural validation beyond "did it parse" is minimal by design.
    // Empty test lists parse fine and aren't an error; suites are allowed to
    // be scaffolds. Extend here as more checks from spec 8.3 are implemented.
    let _ = suite;
    Vec::new()
}
