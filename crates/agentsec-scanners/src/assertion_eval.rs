use agentsec_config::Assertion;

use crate::response::TargetResponse;

/// Result of evaluating one assertion against a captured response.
#[derive(Debug, Clone)]
pub struct AssertionResult {
    pub passed: bool,
    pub description: String,
}

/// Evaluates a single MVP assertion type (spec section 15) against a
/// `TargetResponse`.
pub fn evaluate(assertion: &Assertion, response: &TargetResponse) -> AssertionResult {
    match assertion {
        Assertion::Contains { value } => {
            let passed = response.answer.contains(value.as_str());
            AssertionResult {
                passed,
                description: format!("response should contain \"{value}\""),
            }
        }
        Assertion::NotContains { value } => {
            let passed = !response.answer.contains(value.as_str());
            AssertionResult {
                passed,
                description: format!("response should not contain \"{value}\""),
            }
        }
        Assertion::RegexMatch { pattern } => match regex::Regex::new(pattern) {
            Ok(re) => {
                let passed = re.is_match(&response.answer);
                AssertionResult {
                    passed,
                    description: format!("response should match /{pattern}/"),
                }
            }
            Err(e) => AssertionResult {
                passed: false,
                description: format!("invalid regex pattern /{pattern}/: {e}"),
            },
        },
        Assertion::RegexNotMatch { pattern } => match regex::Regex::new(pattern) {
            Ok(re) => {
                let passed = !re.is_match(&response.answer);
                AssertionResult {
                    passed,
                    description: format!("response should not match /{pattern}/"),
                }
            }
            Err(e) => AssertionResult {
                passed: false,
                description: format!("invalid regex pattern /{pattern}/: {e}"),
            },
        },
        Assertion::JsonPathExists { path } => {
            let passed = json_path_exists(response, path);
            AssertionResult {
                passed,
                description: format!("JSON path {path} should exist in response"),
            }
        }
        Assertion::JsonPathNotExists { path } => {
            let passed = !json_path_exists(response, path);
            AssertionResult {
                passed,
                description: format!("JSON path {path} should not exist in response"),
            }
        }
        Assertion::MaxLength { value } => {
            let passed = response.answer.chars().count() <= *value;
            AssertionResult {
                passed,
                description: format!("response length should be <= {value} chars"),
            }
        }
        Assertion::MaxLatencyMs { value } => {
            let passed = response.latency_ms <= *value;
            AssertionResult {
                passed,
                description: format!("latency should be <= {value}ms"),
            }
        }
        Assertion::ToolNotCalled { tool } => {
            let passed = !response.tool_calls.iter().any(|t| t == tool);
            AssertionResult {
                passed,
                description: format!("tool \"{tool}\" should not be called"),
            }
        }
        Assertion::ToolCalled { tool } => {
            let passed = response.tool_calls.iter().any(|t| t == tool);
            AssertionResult {
                passed,
                description: format!("tool \"{tool}\" should be called"),
            }
        }
        Assertion::CitationsPresent { expected } => {
            let passed = response.citations.is_empty() != *expected;
            AssertionResult {
                passed,
                description: "citations should be present".to_string(),
            }
        }
        Assertion::ForbiddenDomainAbsent { domains } => {
            let passed = !domains.iter().any(|d| response.answer.contains(d.as_str()));
            AssertionResult {
                passed,
                description: format!("response should not reference domains: {domains:?}"),
            }
        }
        Assertion::SecretNotDetected => {
            let matches = crate::data_leakage::detect_secrets(&response.answer);
            AssertionResult {
                passed: matches.is_empty(),
                description: "response should not contain detectable secrets".to_string(),
            }
        }
    }
}

fn json_path_exists(response: &TargetResponse, path: &str) -> bool {
    // MVP: supports the simple `$.field` / `$.a.b` dotted-path subset used
    // throughout the spec's examples, rather than pulling in a full JSONPath
    // engine for this single use case.
    let Some(root) = &response.raw_json else {
        return false;
    };
    let trimmed = path.trim_start_matches('$').trim_start_matches('.');
    if trimmed.is_empty() {
        return true;
    }
    let mut current = root;
    for segment in trimmed.split('.') {
        match current.get(segment) {
            Some(next) => current = next,
            None => return false,
        }
    }
    true
}
