//! Generalized evaluator trait (roadmap Milestone 3).
//!
//! Both deterministic assertions (`assertion_eval.rs`) and built-in
//! scanner detectors (regex/structural checks in `data_leakage.rs`,
//! `output_handling.rs`, `agent_tool.rs`, `rag.rs`,
//! `system_prompt_leakage.rs`) currently report `Finding.confidence` as a
//! hardcoded `1.0`. That's correct today — every evaluator in this crate
//! is fully deterministic, so `1.0` is the honest value, not a stub — but
//! it was hardcoded independently at each call site rather than expressed
//! through a shared abstraction.
//!
//! This module gives every evaluator a single trait to implement so a
//! future probabilistic or LLM-judged evaluator (explicitly out of scope
//! here — see `docs/roadmap.md`'s M3/M4 split) can report a real `<1.0`
//! confidence through the same path, without every caller needing its own
//! ad-hoc confidence field. No evaluator in this file synthesizes a
//! fractional confidence value that isn't backed by real repeated
//! observations; where no repetition data exists, `1.0` is the correct
//! answer, not a placeholder.

use crate::response::TargetResponse;

/// Result of one evaluator's judgment against a captured response.
///
/// `confidence` is in `[0.0, 1.0]`: 1.0 means the evaluator is certain
/// (the normal case for every deterministic evaluator in this crate
/// today), lower values are reserved for evaluators that report a
/// statistically-grounded rate (e.g. an outcome observed across N
/// repetitions) rather than a single yes/no judgment.
#[derive(Debug, Clone)]
pub struct EvaluatorResult {
    pub passed: bool,
    pub confidence: f32,
    pub description: String,
}

/// Common interface for anything that judges a `TargetResponse` and
/// produces a pass/fail verdict with an honest confidence level.
///
/// Implementors: `AssertionEvaluator` (wraps the existing
/// `assertion_eval::evaluate` MVP assertion set) and `DetectorEvaluator`
/// (wraps a scanner's built-in pattern/structural detector). Both are
/// deterministic today and always report `confidence: 1.0`.
pub trait Evaluator {
    /// Machine-readable name for this evaluator, used in finding
    /// descriptions and (eventually) evidence.
    fn name(&self) -> &'static str;

    /// Judges `response`, returning `None` if this evaluator has nothing
    /// to say about it (e.g. a detector whose pattern doesn't match).
    fn evaluate(&self, response: &TargetResponse) -> Option<EvaluatorResult>;
}

/// Wraps a single `Assertion` (spec section 15) as an `Evaluator`.
///
/// Every MVP assertion type is a deterministic string/regex/JSON check
/// against one response, so this always returns `Some` (assertions are
/// unconditional judgments, unlike detectors which may simply not match)
/// with `confidence: 1.0`.
pub struct AssertionEvaluator<'a> {
    pub assertion: &'a agentsec_config::Assertion,
}

impl<'a> Evaluator for AssertionEvaluator<'a> {
    fn name(&self) -> &'static str {
        "assertion"
    }

    fn evaluate(&self, response: &TargetResponse) -> Option<EvaluatorResult> {
        let result = crate::assertion_eval::evaluate(self.assertion, response);
        Some(EvaluatorResult {
            passed: result.passed,
            confidence: 1.0,
            description: result.description,
        })
    }
}

/// Wraps a built-in scanner detector function (a closure returning
/// `Some(description)` on a match, `None` otherwise) as an `Evaluator`.
///
/// Unlike `AssertionEvaluator`, detectors are conditional: `evaluate`
/// returns `None` when the detector simply doesn't fire, matching the
/// existing `finding_for_builtin_match` call sites in `data_leakage.rs`,
/// `output_handling.rs`, `agent_tool.rs`, `rag.rs`, and
/// `system_prompt_leakage.rs`, none of which produce a finding when
/// nothing matches.
pub struct DetectorEvaluator<F>
where
    F: Fn(&TargetResponse) -> Option<String>,
{
    pub name: &'static str,
    pub detect: F,
}

impl<F> Evaluator for DetectorEvaluator<F>
where
    F: Fn(&TargetResponse) -> Option<String>,
{
    fn name(&self) -> &'static str {
        self.name
    }

    fn evaluate(&self, response: &TargetResponse) -> Option<EvaluatorResult> {
        let matched = (self.detect)(response)?;
        Some(EvaluatorResult {
            passed: false,
            confidence: 1.0,
            description: format!("built-in detector matched: {matched}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsec_config::Assertion;

    fn response_with_answer(answer: &str) -> TargetResponse {
        TargetResponse {
            answer: answer.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn assertion_evaluator_reports_full_confidence() {
        let assertion = Assertion::NotContains {
            value: "SECRET".to_string(),
        };
        let evaluator = AssertionEvaluator {
            assertion: &assertion,
        };
        let response = response_with_answer("all clear");
        let result = evaluator
            .evaluate(&response)
            .expect("assertions always judge");
        assert!(result.passed);
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn assertion_evaluator_detects_failure() {
        let assertion = Assertion::NotContains {
            value: "SECRET".to_string(),
        };
        let evaluator = AssertionEvaluator {
            assertion: &assertion,
        };
        let response = response_with_answer("here is the SECRET");
        let result = evaluator
            .evaluate(&response)
            .expect("assertions always judge");
        assert!(!result.passed);
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn detector_evaluator_returns_none_when_no_match() {
        let evaluator = DetectorEvaluator {
            name: "test_detector",
            detect: |r: &TargetResponse| r.answer.contains("bad").then(|| "bad".to_string()),
        };
        let response = response_with_answer("nothing to see here");
        assert!(evaluator.evaluate(&response).is_none());
    }

    #[test]
    fn detector_evaluator_reports_full_confidence_on_match() {
        let evaluator = DetectorEvaluator {
            name: "test_detector",
            detect: |r: &TargetResponse| r.answer.contains("bad").then(|| "bad".to_string()),
        };
        let response = response_with_answer("this is bad");
        let result = evaluator.evaluate(&response).expect("detector matched");
        assert!(!result.passed);
        assert_eq!(result.confidence, 1.0);
        assert_eq!(evaluator.name(), "test_detector");
    }
}
