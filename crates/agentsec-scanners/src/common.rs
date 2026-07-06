use agentsec_config::{Suite, SuiteTest};
use agentsec_core::{Evidence, Finding};

use crate::assertion_eval::{self, AssertionResult};
use crate::response::TargetResponse;

/// Builds a `Finding` for a built-in (non-assertion) detector match — used
/// by scanners that flag patterns beyond what the suite author explicitly
/// asserted (e.g. a generic system-prompt leak phrase, or an unsafe output
/// pattern), per spec sections 14.2, 14.5, and 14.6.
///
/// `matched_detail` is a short, already-safe-to-display description of what
/// was matched (e.g. a phrase or detector kind) — callers must not pass raw
/// secret material here; use `redact::redact_value` first if needed.
pub(crate) fn finding_for_builtin_match(
    scanner_name: &'static str,
    run_id: &str,
    target_id: &str,
    suite: &Suite,
    test: &SuiteTest,
    response: &TargetResponse,
    matched_detail: &str,
) -> Finding {
    Finding {
        id: uuid::Uuid::new_v4().to_string(),
        run_id: run_id.to_string(),
        target_id: target_id.to_string(),
        suite_id: suite.id.clone(),
        test_id: test.id.clone(),
        scanner: scanner_name.to_string(),
        severity: test.severity,
        category: test.category.clone(),
        title: test.title.clone(),
        description: format!("Built-in detector matched: {matched_detail}"),
        owasp: test.owasp.clone(),
        cwe: Vec::new(),
        evidence: Evidence {
            request_summary: response.request_summary.clone(),
            response_summary: response.response_summary(),
            raw_request_path: None,
            raw_response_path: None,
            trace_id: response.trace_id.clone(),
            matched_assertion: Some(matched_detail.to_string()),
            redactions_applied: false,
        },
        recommendation: test.recommendation.clone(),
        references: Vec::new(),
        suppressed: false,
        suppression_reason: None,
    }
}

/// Runs every assertion in `test` against `response`, returning a `Finding`
/// for the *first* failing assertion (spec 12: each suite test maps to at
/// most one finding per run in the MVP model).
pub(crate) fn evaluate_test(
    scanner_name: &'static str,
    run_id: &str,
    target_id: &str,
    suite: &Suite,
    test: &SuiteTest,
    response: &TargetResponse,
) -> Option<Finding> {
    for assertion in &test.assertions {
        let AssertionResult {
            passed,
            description,
        } = assertion_eval::evaluate(assertion, response);
        if !passed {
            return Some(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                run_id: run_id.to_string(),
                target_id: target_id.to_string(),
                suite_id: suite.id.clone(),
                test_id: test.id.clone(),
                scanner: scanner_name.to_string(),
                severity: test.severity,
                category: test.category.clone(),
                title: test.title.clone(),
                description: format!("Assertion failed: {description}"),
                owasp: test.owasp.clone(),
                cwe: Vec::new(),
                evidence: Evidence {
                    request_summary: response.request_summary.clone(),
                    response_summary: response.response_summary(),
                    raw_request_path: None,
                    raw_response_path: None,
                    trace_id: response.trace_id.clone(),
                    matched_assertion: Some(description),
                    redactions_applied: false,
                },
                recommendation: test.recommendation.clone(),
                references: Vec::new(),
                suppressed: false,
                suppression_reason: None,
            });
        }
    }
    None
}
