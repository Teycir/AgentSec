use agentsec_config::{Suite, Target};
use agentsec_core::Finding;
use agentsec_scanners::assertion_eval;
use agentsec_scanners::TargetResponse;
use uuid::Uuid;

use crate::error::RunnerError;
use crate::executor;

/// Outcome of running one suite against one target.
#[derive(Debug, Default)]
pub struct SuiteRunResult {
    pub findings: Vec<Finding>,
    /// Test ids that errored before a response could be scored (network,
    /// auth, extraction failures) rather than failing an assertion.
    pub errors: Vec<(String, String)>,
}

/// Runs every test in `suite` against `target`, turning failed assertions
/// into `Finding`s (spec section 12: one finding per failed assertion).
pub async fn run_suite(
    client: &reqwest::Client,
    run_id: &str,
    target: &Target,
    suite: &Suite,
) -> Result<SuiteRunResult, RunnerError> {
    let mut result = SuiteRunResult::default();
    let mut responses = std::collections::HashMap::new();

    for test in &suite.tests {
        let response = match executor::execute(client, target, &test.input).await {
            Ok(r) => r,
            Err(e) => {
                result.errors.push((test.id.clone(), e.to_string()));
                continue;
            }
        };
        responses.insert(test.id.clone(), response);
    }

    let response_for =
        |t: &agentsec_config::SuiteTest| responses.get(&t.id).cloned().unwrap_or_default();

    use agentsec_scanners::Scanner;
    result
        .findings
        .extend(agentsec_scanners::PromptInjectionScanner.run(
            run_id,
            &target.id,
            suite,
            response_for,
        ));
    result
        .findings
        .extend(agentsec_scanners::SystemPromptLeakageScanner.run(
            run_id,
            &target.id,
            suite,
            response_for,
        ));
    result
        .findings
        .extend(agentsec_scanners::OutputHandlingScanner.run(
            run_id,
            &target.id,
            suite,
            response_for,
        ));
    result
        .findings
        .extend(agentsec_scanners::DataLeakageScanner.run(run_id, &target.id, suite, response_for));

    let scanner_categories = [
        "prompt_injection",
        "system_prompt_leakage",
        "output_handling",
        "data_leakage",
    ];

    for test in &suite.tests {
        if !scanner_categories.contains(&test.category.as_str()) {
            if let Some(response) = responses.get(&test.id) {
                for assertion in &test.assertions {
                    let eval = assertion_eval::evaluate(assertion, response);
                    if !eval.passed {
                        result
                            .findings
                            .push(build_finding(run_id, target, suite, test, response, &eval));
                    }
                }
            }
        }
    }

    Ok(result)
}

fn build_finding(
    run_id: &str,
    target: &Target,
    suite: &Suite,
    test: &agentsec_config::SuiteTest,
    response: &TargetResponse,
    eval: &assertion_eval::AssertionResult,
) -> Finding {
    Finding {
        id: Uuid::new_v4().to_string(),
        run_id: run_id.to_string(),
        target_id: target.id.clone(),
        suite_id: suite.id.clone(),
        test_id: test.id.clone(),
        scanner: test.category.clone(),
        severity: test.severity,
        category: test.category.clone(),
        title: test.title.clone(),
        description: eval.description.clone(),
        owasp: test.owasp.clone(),
        cwe: Vec::new(),
        evidence: agentsec_core::Evidence {
            request_summary: response.request_summary.clone(),
            response_summary: response.response_summary(),
            raw_request_path: None,
            raw_response_path: None,
            trace_id: response.trace_id.clone(),
            matched_assertion: Some(eval.description.clone()),
            redactions_applied: false,
        },
        recommendation: test.recommendation.clone(),
        references: Vec::new(),
        suppressed: false,
        suppression_reason: None,
    }
}
