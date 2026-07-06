//! Prompt injection scanner (spec section 14.1).
//!
//! Purpose: detect whether untrusted user- or retrieved-content can override
//! the application's intended behavior. The MVP relies entirely on the
//! suite author's own assertions (string/regex/JSONPath/latency/length —
//! spec 14.1's "MVP note"), since `semantic_task_completed` is deferred.
//! This scanner's job is simply to select `prompt_injection`-category tests
//! and evaluate them; no additional built-in detector is layered on top,
//! because canary-override detection is exactly what `not_contains`
//! assertions already express.

use agentsec_config::{Suite, SuiteTest};
use agentsec_core::Finding;

use crate::common::evaluate_test;
use crate::response::TargetResponse;
use crate::Scanner;

/// The suite `category` value this scanner claims, per spec section 12's
/// example (`category: prompt_injection`).
pub const CATEGORY: &str = "prompt_injection";

pub struct PromptInjectionScanner;

impl Scanner for PromptInjectionScanner {
    fn name(&self) -> &'static str {
        CATEGORY
    }

    fn run(
        &self,
        run_id: &str,
        target_id: &str,
        suite: &Suite,
        response_for: impl Fn(&SuiteTest) -> TargetResponse,
    ) -> Vec<Finding> {
        suite
            .tests
            .iter()
            .filter(|test| test.category == CATEGORY)
            .filter_map(|test| {
                let response = response_for(test);
                evaluate_test(CATEGORY, run_id, target_id, suite, test, &response)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsec_config::Assertion;
    use agentsec_core::Severity;

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
        let scanner = PromptInjectionScanner;
        let findings = scanner.run("run", "target", &suite, |_| TargetResponse {
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
        let scanner = PromptInjectionScanner;
        let findings = scanner.run("run", "target", &suite, |_| TargetResponse::default());
        assert!(findings.is_empty());
    }
}
