use serde::{Deserialize, Serialize};

/// The outcome of an individual security test execution.
///
/// A security scanner must never confuse an execution failure with a secure result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TestStatus {
    Passed,
    Failed,
    Error,
    Inconclusive,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestOutcome {
    pub test_id: String,
    pub status: TestStatus,
    pub repetitions: usize,
    pub passed_repetitions: usize,
    pub failed_repetitions: usize,
    pub error_repetitions: usize,
    pub confidence: f32,
    #[serde(default)]
    pub reason: Option<String>,
}

impl TestOutcome {
    pub fn passed(test_id: String, repetitions: usize, passed_repetitions: usize) -> Self {
        Self {
            test_id,
            status: TestStatus::Passed,
            repetitions,
            passed_repetitions,
            failed_repetitions: 0,
            error_repetitions: 0,
            confidence: ratio(passed_repetitions, repetitions),
            reason: None,
        }
    }

    pub fn failed(
        test_id: String,
        repetitions: usize,
        passed_repetitions: usize,
        failed_repetitions: usize,
        confidence: f32,
    ) -> Self {
        Self {
            test_id,
            status: TestStatus::Failed,
            repetitions,
            passed_repetitions,
            failed_repetitions,
            error_repetitions: 0,
            confidence,
            reason: None,
        }
    }

    pub fn error(test_id: String, repetitions: usize, errors: usize, reason: String) -> Self {
        Self {
            test_id,
            status: TestStatus::Error,
            repetitions,
            passed_repetitions: 0,
            failed_repetitions: 0,
            error_repetitions: errors,
            confidence: 0.0,
            reason: Some(reason),
        }
    }

    pub fn inconclusive(
        test_id: String,
        repetitions: usize,
        passed_repetitions: usize,
        failed_repetitions: usize,
        error_repetitions: usize,
        reason: String,
    ) -> Self {
        Self {
            test_id,
            status: TestStatus::Inconclusive,
            repetitions,
            passed_repetitions,
            failed_repetitions,
            error_repetitions,
            confidence: ratio(failed_repetitions, repetitions),
            reason: Some(reason),
        }
    }
}

fn ratio(numerator: usize, denominator: usize) -> f32 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f32 / denominator as f32
    }
}
