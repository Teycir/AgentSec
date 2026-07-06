//! agentsec-report: report generation (spec section 17).
//!
//! MVP v0.1 formats: JSON, Markdown, JUnit, and SARIF (SARIF is "strongly
//! recommended" per spec 25, so it's included). HTML (17.5) is explicitly
//! deferred per the MVP scope list.

pub mod junit;
pub mod markdown;
pub mod sarif;
pub mod summary;

pub use summary::{RunReport, RunSummary};

use std::path::Path;

/// Writes every format named in `formats` (as they appear in
/// `ReportSettings.formats`, e.g. `"json"`, `"sarif"`) into `output_dir`.
///
/// Spec 17: each format has a fixed filename under the reports dir.
/// Unknown format strings are ignored here; `agentsec-config::validate`
/// is responsible for rejecting them earlier.
pub fn write_reports(
    report: &RunReport,
    formats: &[String],
    output_dir: &Path,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(output_dir)?;

    for format in formats {
        match format.as_str() {
            "json" => {
                let path = output_dir.join("results.json");
                std::fs::write(path, serde_json::to_string_pretty(report)?)?;
            }
            "sarif" => {
                let path = output_dir.join("results.sarif");
                std::fs::write(
                    path,
                    serde_json::to_string_pretty(&sarif::to_sarif(report))?,
                )?;
            }
            "junit" => {
                let path = output_dir.join("results.junit.xml");
                std::fs::write(path, junit::to_junit_xml(report)?)?;
            }
            "markdown" => {
                let path = output_dir.join("summary.md");
                std::fs::write(path, markdown::to_markdown(report))?;
            }
            // "html" is intentionally unsupported in the MVP (spec 25).
            _ => {}
        }
    }

    Ok(())
}
