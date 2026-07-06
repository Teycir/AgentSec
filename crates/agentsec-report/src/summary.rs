//! The full run report model (spec 17.1: "Must contain project metadata,
//! run metadata, targets, suites, tests, findings, suppressions, baseline
//! comparison, summary counts").

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use agentsec_core::{Finding, Severity};

/// Top-level report written to `results.json` and used to derive every
/// other format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    pub run_id: String,
    pub project_name: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub finished_at: chrono::DateTime<chrono::Utc>,
    pub target_ids: Vec<String>,
    pub suite_ids: Vec<String>,
    pub findings: Vec<Finding>,
    pub summary: RunSummary,
}

/// Severity counts plus pass/fail, used by every report format's headline
/// numbers (spec 17.4's example table).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunSummary {
    pub total_tests_run: usize,
    pub total_findings: usize,
    pub by_severity: BTreeMap<Severity, usize>,
}

impl RunReport {
    /// Builds a report from a completed run's findings, computing the
    /// summary counts. `total_tests_run` is passed in separately since it
    /// includes passing tests, which don't otherwise appear here.
    pub fn new(
        run_id: impl Into<String>,
        project_name: impl Into<String>,
        started_at: chrono::DateTime<chrono::Utc>,
        finished_at: chrono::DateTime<chrono::Utc>,
        target_ids: Vec<String>,
        suite_ids: Vec<String>,
        findings: Vec<Finding>,
        total_tests_run: usize,
    ) -> Self {
        let mut by_severity: BTreeMap<Severity, usize> = BTreeMap::new();
        for finding in &findings {
            if !finding.suppressed {
                *by_severity.entry(finding.severity).or_insert(0) += 1;
            }
        }
        let total_findings = findings.iter().filter(|f| !f.suppressed).count();

        Self {
            run_id: run_id.into(),
            project_name: project_name.into(),
            started_at,
            finished_at,
            target_ids,
            suite_ids,
            findings,
            summary: RunSummary {
                total_tests_run,
                total_findings,
                by_severity,
            },
        }
    }

    /// Highest-severity unsuppressed finding, if any — used by `agentsec
    /// ci` to compare against `ci.fail_on` (spec 9 exit codes).
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings
            .iter()
            .filter(|f| !f.suppressed)
            .map(|f| f.severity)
            .max()
    }
}

// `Severity` needs to be a valid BTreeMap key; it already derives
// Ord/PartialOrd/Eq/PartialEq in agentsec-core, which is sufficient.
