use std::collections::{HashMap, HashSet};

use agentsec_config::{Policies, Suite, SuiteTest, Target};
use agentsec_core::{Evidence, Finding, SessionTrace, SessionTurn, Severity, TestOutcome, TestStatus};
use agentsec_scanners::{assertion_eval, Scanner, TargetResponse};
use uuid::Uuid;

use crate::error::RunnerError;
use crate::executor;

/// Outcome of running one suite against one target.
#[derive(Debug, Default)]
pub struct SuiteRunResult {
    pub findings: Vec<Finding>,
    /// Tests that errored before a response could be scored.
    pub errors: Vec<(String, String)>,
    /// Explicit outcome for every test, including PASS/FAIL/ERROR/INCONCLUSIVE.
    pub outcomes: Vec<TestOutcome>,
    /// Provider-neutral trace of the executed session.
    pub session: Option<SessionTrace>,
}

/// Runs a suite with explicit result semantics, repeated executions, confidence,
/// session tracing, and sanitized evidence.
pub async fn run_suite(
    client: &reqwest::Client,
    run_id: &str,
    target: &Target,
    suite: &Suite,
    limits: Option<&agentsec_config::project::LimitsSettings>,
    policies: Option<&Policies>,
) -> Result<SuiteRunResult, RunnerError> {
    let mut result = SuiteRunResult::default();
    let mut session = SessionTrace::new(run_id);
    let mut responses_by_test: HashMap<String, Vec<TargetResponse>> = HashMap::new();
    let mut cumulative_tokens = 0usize;

    for test in &suite.tests {
        let repetitions = test.repetitions.max(1);
        let mut passed = 0usize;
        let mut failed = 0usize;
        let mut errors = 0usize;
        let mut first_error = None;

        for repetition in 0..repetitions {
            let started = std::time::Instant::now();
            let response = match executor::execute(client, target, &test.input).await {
                Ok(response) => response,
                Err(error) => {
                    errors += 1;
                    first_error.get_or_insert_with(|| error.to_string());
                    continue;
                }
            };

            let latency_ms = started.elapsed().as_millis() as u64;
            let estimated_tokens = response.answer.chars().count() / 4;
            cumulative_tokens += estimated_tokens;
            responses_by_test
                .entry(test.id.clone())
                .or_default()
                .push(response.clone());

            session.push_turn(SessionTurn {
                sequence: repetition,
                test_id: test.id.clone(),
                trace_id: response.trace_id.clone(),
                tool_calls: response.tool_calls.clone(),
                retrieved_context: response.retrieved_context.clone(),
            });

            if let Some(max_latency) = limits.and_then(|l| l.max_latency_per_request_ms) {
                if latency_ms > max_latency {
                    result.findings.push(resource_finding(
                        run_id,
                        target,
                        suite,
                        test,
                        &response,
                        "Latency Limit Exceeded",
                        format!("Request latency of {latency_ms}ms exceeded the configured maximum of {max_latency}ms"),
                        format!("latency ({latency_ms}ms) > limit ({max_latency}ms)"),
                        1.0 / repetitions as f32,
                    ));
                }
            }

            if let Some(max_tokens) = limits.and_then(|l| l.max_tokens_per_session) {
                if cumulative_tokens > max_tokens {
                    result.findings.push(resource_finding(
                        run_id,
                        target,
                        suite,
                        test,
                        &response,
                        "Session Token Limit Exceeded",
                        format!("Cumulative estimated tokens of {cumulative_tokens} exceeded the configured maximum of {max_tokens}"),
                        format!("estimated tokens ({cumulative_tokens}) > limit ({max_tokens})"),
                        1.0,
                    ));
                    break;
                }
            }

            let assertions_pass = test.assertions.iter().all(|assertion| {
                assertion_eval::evaluate(assertion, &response).passed
            });
            if assertions_pass {
                passed += 1;
            } else {
                failed += 1;
            }
        }

        let required_passes = test.min_passes.unwrap_or(repetitions);
        let status = if errors == repetitions {
            TestStatus::Error
        } else if passed >= required_passes {
            TestStatus::Passed
        } else if errors > 0 {
            TestStatus::Inconclusive
        } else {
            TestStatus::Failed
        };

        let confidence = if repetitions == 0 {
            0.0
        } else {
            failed as f32 / repetitions as f32
        };

        let outcome = match status {
            TestStatus::Passed => TestOutcome::passed(test.id.clone(), repetitions, passed),
            TestStatus::Failed => TestOutcome::failed(
                test.id.clone(),
                repetitions,
                passed,
                failed,
                confidence,
            ),
            TestStatus::Error => TestOutcome::error(
                test.id.clone(),
                repetitions,
                errors,
                first_error.clone().unwrap_or_else(|| "execution failed".to_string()),
            ),
            TestStatus::Inconclusive => TestOutcome::inconclusive(
                test.id.clone(),
                repetitions,
                passed,
                failed,
                errors,
                first_error.clone().unwrap_or_else(|| "mixed execution results".to_string()),
            ),
            TestStatus::Skipped => unreachable!(),
        };
        result.outcomes.push(outcome);

        if status == TestStatus::Failed {
            if let Some(responses) = responses_by_test.get(&test.id) {
                if let Some(response) = responses.first() {
                    for assertion in &test.assertions {
                        let evaluation = assertion_eval::evaluate(assertion, response);
                        if !evaluation.passed {
                            result.findings.push(build_finding(
                                run_id,
                                target,
                                suite,
                                test,
                                response,
                                &evaluation,
                                confidence,
                            ));
                        }
                    }
                }
            }
        }
    }

    // Run built-in scanners once per repetition and merge duplicate findings.
    let mut merged: HashMap<String, Finding> = HashMap::new();
    let scanner_categories: HashSet<&str> = [
        "prompt_injection",
        "system_prompt_leakage",
        "output_handling",
        "data_leakage",
        "rag",
        "agent_tool",
    ]
    .into_iter()
    .collect();

    for test in &suite.tests {
        let responses = responses_by_test.get(&test.id).cloned().unwrap_or_default();
        let repetitions = test.repetitions.max(1);
        for response in responses {
            let response_for = |candidate: &SuiteTest| {
                if candidate.id == test.id {
                    response.clone()
                } else {
                    TargetResponse::default()
                }
            };
            let scanners: Vec<Box<dyn Scanner>> = vec![
                Box::new(agentsec_scanners::PromptInjectionScanner),
                Box::new(agentsec_scanners::SystemPromptLeakageScanner),
                Box::new(agentsec_scanners::OutputHandlingScanner),
                Box::new(agentsec_scanners::DataLeakageScanner),
                Box::new(agentsec_scanners::RagScanner),
                Box::new(agentsec_scanners::AgentToolScanner {
                    policy: policies.and_then(|p| p.tool_calls.as_ref()),
                }),
            ];
            for scanner in scanners {
                for finding in scanner.run(run_id, &target.id, suite, response_for) {
                    if !scanner_categories.contains(finding.category.as_str()) {
                        continue;
                    }
                    let key = format!("{}:{}", finding.scanner, finding.stable_key());
                    if let Some(existing) = merged.get_mut(&key) {
                        existing.confidence = (existing.confidence + 1.0 / repetitions as f32).min(1.0);
                    } else {
                        let mut finding = finding;
                        finding.confidence = 1.0 / repetitions as f32;
                        finding.evidence.request_summary = agentsec_scanners::redact::sanitize_evidence_text(&finding.evidence.request_summary);
                        finding.evidence.response_summary = agentsec_scanners::redact::sanitize_evidence_text(&finding.evidence.response_summary);
                        finding.evidence.redactions_applied = true;
                        merged.insert(key, finding);
                    }
                }
            }
        }
    }

    result.findings.extend(merged.into_values());
    result.errors.extend(
        result
            .outcomes
            .iter()
            .filter_map(|outcome| outcome.reason.clone().map(|reason| (outcome.test_id.clone(), reason))),
    );
    result.session = Some(session);
    Ok(result)
}

fn build_finding(
    run_id: &str,
    target: &Target,
    suite: &Suite,
    test: &SuiteTest,
    response: &TargetResponse,
    eval: &assertion_eval::AssertionResult,
    confidence: f32,
) -> Finding {
    Finding {
        id: Uuid::new_v4().to_string(),
        run_id: run_id.to_string(),
        target_id: target.id.clone(),
        suite_id: suite.id.clone(),
        test_id: test.id.clone(),
        scanner: test.category.clone(),
        severity: test.severity,
        confidence,
        category: test.category.clone(),
        title: test.title.clone(),
        description: agentsec_scanners::redact::sanitize_evidence_text(&eval.description),
        owasp: test.owasp.clone(),
        cwe: Vec::new(),
        evidence: sanitized_evidence(response, Some(eval.description.clone())),
        recommendation: test.recommendation.clone(),
        references: Vec::new(),
        suppressed: false,
        suppression_reason: None,
    }
}

fn resource_finding(
    run_id: &str,
    target: &Target,
    suite: &Suite,
    test: &SuiteTest,
    response: &TargetResponse,
    title: &str,
    description: String,
    assertion: String,
    confidence: f32,
) -> Finding {
    Finding {
        id: Uuid::new_v4().to_string(),
        run_id: run_id.to_string(),
        target_id: target.id.clone(),
        suite_id: suite.id.clone(),
        test_id: test.id.clone(),
        scanner: "resource_exhaustion".to_string(),
        severity: Severity::High,
        confidence,
        category: "resource_exhaustion".to_string(),
        title: title.to_string(),
        description: agentsec_scanners::redact::sanitize_evidence_text(&description),
        owasp: vec!["LLM04: Model Denial of Service".to_string()],
        cwe: Vec::new(),
        evidence: sanitized_evidence(response, Some(assertion)),
        recommendation: "Review resource limits, capacity, and model/provider configuration.".to_string(),
        references: Vec::new(),
        suppressed: false,
        suppression_reason: None,
    }
}

fn sanitized_evidence(response: &TargetResponse, matched_assertion: Option<String>) -> Evidence {
    Evidence {
        request_summary: agentsec_scanners::redact::sanitize_evidence_text(&response.request_summary),
        response_summary: agentsec_scanners::redact::sanitize_evidence_text(&response.response_summary()),
        raw_request_path: None,
        raw_response_path: None,
        trace_id: response.trace_id.clone(),
        matched_assertion,
        redactions_applied: true,
    }
}
