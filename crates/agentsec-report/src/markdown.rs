//! Markdown report (spec 17.4) — for PR comments.

use agentsec_core::Severity;

use crate::summary::RunReport;

/// Renders the exact layout shown in spec 17.4: an H1 title, a target
/// line, a severity count table (worst-to-best), then a findings list
/// with `### SEVERITY: Title`, OWASP line, description, and
/// recommendation.
pub fn to_markdown(report: &RunReport) -> String {
    let mut out = String::new();
    out.push_str("# AgentSec Summary\n\n");

    for target_id in &report.target_ids {
        out.push_str(&format!("Target: `{target_id}`\n\n"));
    }

    out.push_str("| Severity | Count |\n|---|---:|\n");
    for severity in Severity::ALL.iter().rev() {
        let count = report
            .summary
            .by_severity
            .get(severity)
            .copied()
            .unwrap_or(0);
        out.push_str(&format!("| {} | {count} |\n", severity_label(*severity)));
    }
    out.push('\n');

    out.push_str("## Findings\n\n");
    if report.findings.iter().all(|f| f.suppressed) {
        out.push_str("_No findings._\n");
        return out;
    }

    for finding in report.findings.iter().filter(|f| !f.suppressed) {
        out.push_str(&format!(
            "### {}: {}\n\n",
            severity_label(finding.severity).to_uppercase(),
            finding.title
        ));
        if !finding.owasp.is_empty() {
            out.push_str(&format!("OWASP: {}\n\n", finding.owasp.join(", ")));
        }
        out.push_str(&format!("{}\n\n", finding.description));
        if !finding.recommendation.is_empty() {
            out.push_str(&format!("Recommendation:\n{}\n\n", finding.recommendation));
        }
    }

    out
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "Info",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}
