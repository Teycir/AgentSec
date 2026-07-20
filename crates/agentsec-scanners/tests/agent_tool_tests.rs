//! Integration tests for `agentsec_scanners::agent_tool`.

use agentsec_config::{Assertion, Suite, SuiteTest, ToolCallPolicy};
use agentsec_core::Severity;
use agentsec_scanners::response::TargetResponse;
use agentsec_scanners::{AgentToolScanner, Scanner};

fn suite_with_test(test: SuiteTest) -> Suite {
    Suite {
        id: "s".to_string(),
        name: "s".to_string(),
        description: String::new(),
        version: "1".to_string(),
        tests: vec![test],
    }
}

fn base_test(id: &str, assertions: Vec<Assertion>) -> SuiteTest {
    SuiteTest {
        id: id.to_string(),
        title: "title".to_string(),
        severity: Severity::Critical,
        category: "agent_tool".to_string(),
        owasp: Vec::new(),
        input: "input".to_string(),
        assertions,
        recommendation: String::new(),
        repetitions: 1,
        min_passes: None,
    }
}

fn response_with_tools(tool_calls: &[&str]) -> TargetResponse {
    TargetResponse {
        answer: "ok".to_string(),
        tool_calls: tool_calls.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

fn policy() -> ToolCallPolicy {
    ToolCallPolicy {
        allowed_tools: vec!["search_docs".to_string()],
        forbidden_tools: vec![
            "delete_ticket".to_string(),
            "update_permissions".to_string(),
        ],
        require_human_approval: vec!["send_email".to_string()],
    }
}

#[test]
fn ignores_other_categories() {
    let mut test = base_test("t1", vec![]);
    test.category = "prompt_injection".to_string();
    let suite = suite_with_test(test);
    let response = response_with_tools(&["delete_ticket"]);
    let policy = policy();
    let findings = AgentToolScanner {
        policy: Some(&policy),
    }
    .run("run-1", "target-1", &suite, |_| response.clone());
    assert!(findings.is_empty());
}
#[test]
fn no_policy_configured_only_evaluates_assertions() {
    let test = base_test(
        "t1",
        vec![Assertion::ToolNotCalled {
            tool: "delete_ticket".to_string(),
        }],
    );
    let suite = suite_with_test(test);
    let response = response_with_tools(&["delete_ticket"]);
    let findings =
        AgentToolScanner { policy: None }.run("run-1", "target-1", &suite, |_| response.clone());
    assert_eq!(findings.len(), 1);
    assert!(findings[0].description.contains("Assertion failed"));
}
#[test]
fn assertion_failure_takes_priority_over_policy_detector() {
    let test = base_test(
        "t1",
        vec![Assertion::ToolNotCalled {
            tool: "delete_ticket".to_string(),
        }],
    );
    let suite = suite_with_test(test);
    let response = response_with_tools(&["delete_ticket"]);
    let policy = policy();
    let findings = AgentToolScanner {
        policy: Some(&policy),
    }
    .run("run-1", "target-1", &suite, |_| response.clone());
    assert_eq!(findings.len(), 1);
    assert!(findings[0].description.contains("Assertion failed"));
}
#[test]
fn policy_detector_flags_forbidden_tool_with_no_explicit_assertion() {
    let test = base_test(
        "t1",
        vec![Assertion::ToolCalled {
            tool: "search_docs".to_string(),
        }],
    );
    let suite = suite_with_test(test);
    let response = response_with_tools(&["search_docs", "update_permissions"]);
    let policy = policy();
    let findings = AgentToolScanner {
        policy: Some(&policy),
    }
    .run("run-1", "target-1", &suite, |_| response.clone());
    assert_eq!(findings.len(), 1);
    assert!(findings[0]
        .description
        .contains("Built-in detector matched"));
    assert!(findings[0]
        .evidence
        .matched_assertion
        .as_deref()
        .unwrap()
        .contains("update_permissions"));
}
#[test]
fn allowed_tool_only_produces_no_finding() {
    let test = base_test(
        "t1",
        vec![Assertion::ToolCalled {
            tool: "search_docs".to_string(),
        }],
    );
    let suite = suite_with_test(test);
    let response = response_with_tools(&["search_docs"]);
    let policy = policy();
    let findings = AgentToolScanner {
        policy: Some(&policy),
    }
    .run("run-1", "target-1", &suite, |_| response.clone());
    assert!(findings.is_empty());
}
#[test]
fn require_human_approval_tools_are_not_auto_flagged() {
    let test = base_test("t1", vec![]);
    let suite = suite_with_test(test);
    let response = response_with_tools(&["send_email"]);
    let policy = policy();
    let findings = AgentToolScanner {
        policy: Some(&policy),
    }
    .run("run-1", "target-1", &suite, |_| response.clone());
    assert!(findings.is_empty());
}
