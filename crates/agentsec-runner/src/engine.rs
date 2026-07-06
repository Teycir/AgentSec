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
    limits: Option<&agentsec_config::project::LimitsSettings>,
) -> Result<SuiteRunResult, RunnerError> {
    let mut result = SuiteRunResult::default();
    let mut responses = std::collections::HashMap::new();
    let mut cumulative_tokens = 0;

    for test in &suite.tests {
        let started = std::time::Instant::now();
        let response = match executor::execute(client, target, &test.input).await {
            Ok(r) => r,
            Err(e) => {
                result.errors.push((test.id.clone(), e.to_string()));
                continue;
            }
        };
        let request_latency_ms = started.elapsed().as_millis() as u64;
        let estimated_tokens = response.answer.chars().count() / 4;
        cumulative_tokens += estimated_tokens;

        responses.insert(test.id.clone(), response.clone());

        if let Some(limits) = limits {
            if let Some(max_latency) = limits.max_latency_per_request_ms {
                if request_latency_ms > max_latency {
                    result.findings.push(Finding {
                        id: format!("{}:{}:resource_exhaustion_latency", target.id, suite.id),
                        run_id: run_id.to_string(),
                        target_id: target.id.clone(),
                        suite_id: suite.id.clone(),
                        test_id: test.id.clone(),
                        scanner: "resource_exhaustion".to_string(),
                        severity: agentsec_core::Severity::Critical,
                        category: "resource_exhaustion".to_string(),
                        title: "Latency Limit Exceeded".to_string(),
                        description: format!(
                            "Request latency of {}ms exceeded the configured maximum of {}ms",
                            request_latency_ms, max_latency
                        ),
                        owasp: vec!["LLM04: Model Denial of Service".to_string()],
                        cwe: Vec::new(),
                        evidence: agentsec_core::finding::Evidence {
                            request_summary: response.request_summary.clone(),
                            response_summary: response.response_summary(),
                            raw_request_path: None,
                            raw_response_path: None,
                            trace_id: response.trace_id.clone(),
                            matched_assertion: Some(format!(
                                "latency ({}ms) > limit ({}ms)",
                                request_latency_ms, max_latency
                            )),
                            redactions_applied: false,
                        },
                        recommendation: "Ensure the model endpoint scale is sufficient, optimize prompt context size, or increase configured limits.".to_string(),
                        references: Vec::new(),
                        suppressed: false,
                        suppression_reason: None,
                    });
                    break;
                }
            }

            if let Some(max_tokens) = limits.max_tokens_per_session {
                if cumulative_tokens > max_tokens {
                    result.findings.push(Finding {
                        id: format!("{}:{}:resource_exhaustion_tokens", target.id, suite.id),
                        run_id: run_id.to_string(),
                        target_id: target.id.clone(),
                        suite_id: suite.id.clone(),
                        test_id: test.id.clone(),
                        scanner: "resource_exhaustion".to_string(),
                        severity: agentsec_core::Severity::Critical,
                        category: "resource_exhaustion".to_string(),
                        title: "Session Token Limit Exceeded".to_string(),
                        description: format!(
                            "Cumulative session tokens of {} exceeded the configured maximum of {}",
                            cumulative_tokens, max_tokens
                        ),
                        owasp: vec!["LLM04: Model Denial of Service".to_string()],
                        cwe: Vec::new(),
                        evidence: agentsec_core::finding::Evidence {
                            request_summary: response.request_summary.clone(),
                            response_summary: response.response_summary(),
                            raw_request_path: None,
                            raw_response_path: None,
                            trace_id: response.trace_id.clone(),
                            matched_assertion: Some(format!(
                                "cumulative tokens ({}) > limit ({})",
                                cumulative_tokens, max_tokens
                            )),
                            redactions_applied: false,
                        },
                        recommendation: "Implement token budgeting, limit response max_tokens, or increase configured session limit.".to_string(),
                        references: Vec::new(),
                        suppressed: false,
                        suppression_reason: None,
                    });
                    break;
                }
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use agentsec_config::target::TargetKind;
    use agentsec_config::{Suite, SuiteTest, Target};
    use agentsec_core::Severity;

    async fn run_mock_server(response_body: &'static str, delay_ms: u64) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let addr = format!("http://127.0.0.1:{}", port);

        tokio::spawn(async move {
            listener.set_nonblocking(true).unwrap();
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0; 1024];
                    if socket.read(&mut buf).await.is_ok() {
                        if delay_ms > 0 {
                            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        }
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            response_body.len(),
                            response_body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                        let _ = socket.flush().await;
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_runner_real_http_limits_and_schema() {
        // Spin up a local mock server returning valid JSON matching a schema
        let server_addr = run_mock_server(r#"{"status": "ok", "tokens": 100}"#, 50).await;

        let client = reqwest::Client::new();
        let target = Target {
            id: "test-target".to_string(),
            kind: TargetKind::HttpChat {
                base_url: server_addr.clone(),
                request: agentsec_config::target::HttpRequestSpec {
                    method: "POST".to_string(),
                    path: "/chat".to_string(),
                    headers: std::collections::HashMap::new(),
                    body: serde_json::json!({ "prompt": "{{ input }}" }),
                },
                response: agentsec_config::target::HttpResponseSpec {
                    answer_json_path: "$".to_string(),
                    citations_json_path: None,
                    tool_calls_json_path: None,
                    trace_id_json_path: None,
                    retrieved_context_json_path: None,
                },
                capabilities: Default::default(),
            },
        };

        // Create a suite with a JSON schema match assertion
        let suite = Suite {
            id: "test-suite".to_string(),
            name: "Test Suite".to_string(),
            description: String::new(),
            version: "1".to_string(),
            tests: vec![SuiteTest {
                id: "test-1".to_string(),
                title: "Test JSON schema".to_string(),
                severity: Severity::High,
                category: "custom".to_string(),
                owasp: Vec::new(),
                input: "hello".to_string(),
                assertions: vec![agentsec_config::Assertion::JsonSchemaMatch {
                    schema: r#"{"type": "object", "required": ["status"]}"#.to_string(),
                }],
                recommendation: String::new(),
            }],
        };

        // 1. Run without limits
        let res = run_suite(&client, "run-1", &target, &suite, None)
            .await
            .unwrap();
        assert!(res.errors.is_empty());
        assert!(
            res.findings.is_empty(),
            "Findings should be empty, schema passed"
        );

        // 2. Run with latency limit exceeded
        let server_addr_slow = run_mock_server(r#"{"status": "ok"}"#, 100).await;
        let (request, response) = match &target.kind {
            TargetKind::HttpChat {
                request, response, ..
            } => (request.clone(), response.clone()),
            _ => unreachable!(),
        };
        let target_slow = Target {
            id: "test-target-slow".to_string(),
            kind: TargetKind::HttpChat {
                base_url: server_addr_slow,
                request,
                response,
                capabilities: Default::default(),
            },
        };
        let limits = agentsec_config::project::LimitsSettings {
            max_tokens_per_session: None,
            max_latency_per_request_ms: Some(10), // Limit is 10ms, server takes 100ms
        };
        let res = run_suite(&client, "run-2", &target_slow, &suite, Some(&limits))
            .await
            .unwrap();
        assert_eq!(res.findings.len(), 1);
        assert_eq!(res.findings[0].category, "resource_exhaustion");
        assert!(res.findings[0].title.contains("Latency"));
    }
}
