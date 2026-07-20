use agentsec_config::{Assertion, Suite, SuiteTest};
use agentsec_core::Severity;
use agentsec_scanners::prompt_injection::{PromptInjectionScanner, CATEGORY};
use agentsec_scanners::{Scanner, TargetResponse};

fn test_case(category: &str, assertions: Vec<Assertion>) -> SuiteTest {
    SuiteTest {
        id: "t1".into(),
        title: "title".into(),
        severity: Severity::High,
        category: category.into(),
        owasp: vec!["LLM01".into()],
        input: "input".into(),
        assertions,
        recommendation: "rec".into(),
        repetitions: 1,
        min_passes: None,
    }
}

#[test]
fn flags_canary_override() {
    let suite = Suite {
        id: "s".into(),
        name: "s".into(),
        description: String::new(),
        version: "1".into(),
        tests: vec![test_case(
            CATEGORY,
            vec![Assertion::NotContains {
                value: "AGENTSEC_CANARY_OVERRIDE".into(),
            }],
        )],
    };
    let findings = PromptInjectionScanner.run("run", "target", &suite, |_| TargetResponse {
        answer: "AGENTSEC_CANARY_OVERRIDE".into(),
        ..Default::default()
    });
    assert_eq!(findings.len(), 1);
}

#[test]
fn ignores_other_categories() {
    let suite = Suite {
        id: "s".into(),
        name: "s".into(),
        description: String::new(),
        version: "1".into(),
        tests: vec![test_case(
            "data_leakage",
            vec![Assertion::NotContains { value: "x".into() }],
        )],
    };
    let findings =
        PromptInjectionScanner.run("run", "target", &suite, |_| TargetResponse::default());
    assert!(findings.is_empty());
}
