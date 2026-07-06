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
    #[error("duplicate test id '{test_id}' in suite '{suite_id}'")]
    DuplicateTestId { suite_id: String, test_id: String },
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
///
/// Currently checks: duplicate `test.id` within the suite. A duplicate test
/// id breaks `Finding::stable_key()` (`target:suite:test`) uniqueness, which
/// baselines and suppressions rely on — two distinct tests would share a
/// suppression/baseline entry and be indistinguishable from one another.
pub fn validate_suite(suite: &Suite) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    let mut seen_ids = std::collections::HashSet::new();
    for test in &suite.tests {
        if !seen_ids.insert(test.id.clone()) {
            errors.push(ValidationError::DuplicateTestId {
                suite_id: suite.id.clone(),
                test_id: test.id.clone(),
            });
        }
    }

    // MVP: structural validation beyond "did it parse" and duplicate-id
    // checking is minimal by design. Empty test lists parse fine and aren't
    // an error; suites are allowed to be scaffolds. Extend here as more
    // checks from spec 8.3 are implemented.
    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::SuiteTest;
    use agentsec_core::Severity;

    fn test_case(id: &str) -> SuiteTest {
        SuiteTest {
            id: id.to_string(),
            title: "title".to_string(),
            severity: Severity::Medium,
            category: "prompt_injection".to_string(),
            owasp: Vec::new(),
            input: "input".to_string(),
            assertions: Vec::new(),
            recommendation: String::new(),
        }
    }

    fn suite_with(tests: Vec<SuiteTest>) -> Suite {
        Suite {
            id: "s".to_string(),
            name: "s".to_string(),
            description: String::new(),
            version: "1".to_string(),
            tests,
        }
    }

    #[test]
    fn empty_suite_has_no_errors() {
        assert!(validate_suite(&suite_with(Vec::new())).is_empty());
    }

    #[test]
    fn unique_test_ids_have_no_errors() {
        let suite = suite_with(vec![test_case("a"), test_case("b")]);
        assert!(validate_suite(&suite).is_empty());
    }

    #[test]
    fn duplicate_test_id_is_flagged() {
        let suite = suite_with(vec![test_case("dup"), test_case("dup")]);
        let errors = validate_suite(&suite);
        assert_eq!(errors.len(), 1);
        match &errors[0] {
            ValidationError::DuplicateTestId { suite_id, test_id } => {
                assert_eq!(suite_id, "s");
                assert_eq!(test_id, "dup");
            }
            other => panic!("expected DuplicateTestId, got {other:?}"),
        }
    }

    #[test]
    fn each_extra_duplicate_occurrence_is_flagged() {
        // 3 tests sharing one id -> 2 duplicate reports (the 2nd and 3rd
        // occurrence), matching the same "flag every extra occurrence"
        // pattern as validate_config's DuplicateTargetId check.
        let suite = suite_with(vec![test_case("dup"), test_case("dup"), test_case("dup")]);
        assert_eq!(validate_suite(&suite).len(), 2);
    }
}
