//! HTML report (spec section 17.5 / section 4 format list).
//!
//! A single self-contained static file: no external CSS/JS, safe to open
//! from disk or attach to a CI artifact. Renders the same `RunReport` data
//! as `markdown.rs`/`sarif.rs` — severity counts as a stacked "risk spine",
//! then one card per unsuppressed finding grouped by severity (worst first).

use agentsec_core::{Finding, Severity};

use crate::summary::RunReport;

/// Renders a complete HTML document for `report`.
pub fn to_html(report: &RunReport) -> String {
    let body = render_body(report);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AgentSec Lab Report — {run_id}</title>
<style>
{css}
</style>
</head>
<body>
{body}
</body>
</html>
"#,
        run_id = escape(&report.run_id),
        css = CSS,
        body = body,
    )
}

const CSS: &str = r#"
:root {
  --ink:        #E8E6E1;
  --ink-dim:    #9B9890;
  --surface:    #14171C;
  --surface-2:  #1B1F26;
  --line:       #2A2F38;
  --accent:     #E0A75E;
  --accent-dim: #8A6B3C;
  --info:       #5B7A94;
  --low:        #6E8B5E;
  --medium:     #C9A227;
  --high:       #D0743C;
  --critical:   #C1443C;
  --mono: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --sans: "IBM Plex Sans", -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
}

@media (prefers-color-scheme: light) {
  :root {
    --ink: #1C1F24; --ink-dim: #5C6068;
    --surface: #FAF9F7; --surface-2: #F1EEE9; --line: #DEDAD2;
  }
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--surface);
  color: var(--ink);
  font-family: var(--sans);
  line-height: 1.5;
}

.report {
  max-width: 880px;
  margin: 0 auto;
  padding: 3rem 1.5rem 5rem;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 1rem;
  border-bottom: 1px solid var(--line);
  padding-bottom: 1.25rem;
  margin-bottom: 2rem;
  flex-wrap: wrap;
}

.header h1 {
  font-size: 1.375rem;
  font-weight: 600;
  letter-spacing: -0.01em;
  margin: 0;
}

.header .meta {
  font-family: var(--mono);
  font-size: 0.8125rem;
  color: var(--ink-dim);
  text-align: right;
}

.targets {
  font-family: var(--mono);
  font-size: 0.8125rem;
  color: var(--ink-dim);
  margin-bottom: 2rem;
}

.targets code {
  color: var(--accent);
  background: var(--surface-2);
  padding: 0.1rem 0.4rem;
  border-radius: 3px;
}

/* --- Risk spine: the signature element. A single stacked bar showing
   the proportion of findings at each severity, worst-first left to
   right, with the counts as its own legend row underneath. --- */

.spine {
  margin-bottom: 2.5rem;
}

.spine-bar {
  display: flex;
  height: 10px;
  border-radius: 5px;
  overflow: hidden;
  background: var(--surface-2);
  border: 1px solid var(--line);
}

.spine-bar .seg { height: 100%; }
.spine-bar .seg.critical { background: var(--critical); }
.spine-bar .seg.high     { background: var(--high); }
.spine-bar .seg.medium   { background: var(--medium); }
.spine-bar .seg.low      { background: var(--low); }
.spine-bar .seg.info     { background: var(--info); }

.spine-legend {
  display: flex;
  gap: 1.5rem;
  margin-top: 0.9rem;
  flex-wrap: wrap;
}

.spine-legend .item {
  display: flex;
  align-items: baseline;
  gap: 0.4rem;
  font-family: var(--mono);
  font-size: 0.8125rem;
}

.spine-legend .dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  transform: translateY(1px);
}
.spine-legend .dot.critical { background: var(--critical); }
.spine-legend .dot.high     { background: var(--high); }
.spine-legend .dot.medium   { background: var(--medium); }
.spine-legend .dot.low      { background: var(--low); }
.spine-legend .dot.info     { background: var(--info); }

.spine-legend .count { color: var(--ink); font-weight: 600; }
.spine-legend .label { color: var(--ink-dim); }

.section-title {
  font-family: var(--mono);
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--ink-dim);
  margin: 2.5rem 0 0.9rem;
}

.empty {
  font-family: var(--mono);
  color: var(--ink-dim);
  font-size: 0.9rem;
  padding: 1.5rem 0;
}

.finding {
  border: 1px solid var(--line);
  border-left: 3px solid var(--sev-color, var(--info));
  background: var(--surface-2);
  border-radius: 6px;
  padding: 1.1rem 1.25rem;
  margin-bottom: 0.9rem;
}

.finding[data-severity="critical"] { --sev-color: var(--critical); }
.finding[data-severity="high"]     { --sev-color: var(--high); }
.finding[data-severity="medium"]   { --sev-color: var(--medium); }
.finding[data-severity="low"]      { --sev-color: var(--low); }
.finding[data-severity="info"]     { --sev-color: var(--info); }

.finding-head {
  display: flex;
  align-items: baseline;
  gap: 0.6rem;
  flex-wrap: wrap;
  margin-bottom: 0.4rem;
}

.badge {
  font-family: var(--mono);
  font-size: 0.6875rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--sev-color, var(--info));
  border: 1px solid var(--sev-color, var(--info));
  border-radius: 3px;
  padding: 0.1rem 0.4rem;
}

.finding-title { font-weight: 600; font-size: 0.975rem; }

.finding-sub {
  font-family: var(--mono);
  font-size: 0.75rem;
  color: var(--ink-dim);
  margin-bottom: 0.6rem;
}

.finding p.desc { margin: 0.5rem 0; font-size: 0.9rem; }

.finding .owasp {
  display: inline-block;
  font-family: var(--mono);
  font-size: 0.7rem;
  color: var(--accent);
  margin-bottom: 0.5rem;
}

details.evidence {
  margin-top: 0.7rem;
  border-top: 1px dashed var(--line);
  padding-top: 0.6rem;
}

details.evidence summary {
  cursor: pointer;
  font-family: var(--mono);
  font-size: 0.75rem;
  color: var(--ink-dim);
  user-select: none;
}

details.evidence summary:hover { color: var(--accent); }

.evidence pre {
  font-family: var(--mono);
  font-size: 0.8rem;
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 0.75rem;
  margin: 0.6rem 0;
  white-space: pre-wrap;
  word-break: break-word;
}

.recommendation {
  margin-top: 0.7rem;
  font-size: 0.875rem;
  padding-top: 0.6rem;
  border-top: 1px solid var(--line);
}

.recommendation .label {
  font-family: var(--mono);
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--accent-dim);
  display: block;
  margin-bottom: 0.25rem;
}

.footer {
  margin-top: 3rem;
  padding-top: 1.25rem;
  border-top: 1px solid var(--line);
  font-family: var(--mono);
  font-size: 0.75rem;
  color: var(--ink-dim);
}

"#;

fn render_body(report: &RunReport) -> String {
    let mut out = String::new();
    out.push_str("<div class=\"report\">\n");

    out.push_str(&format!(
        "<div class=\"header\">\n<h1>AgentSec Lab Report</h1>\n<div class=\"meta\">{project}<br>{finished}</div>\n</div>\n",
        project = escape(&report.project_name),
        finished = escape(&report.finished_at.to_rfc3339()),
    ));

    if !report.target_ids.is_empty() {
        out.push_str("<div class=\"targets\">Targets: ");
        let rendered: Vec<String> = report
            .target_ids
            .iter()
            .map(|t| format!("<code>{}</code>", escape(t)))
            .collect();
        out.push_str(&rendered.join(" "));
        out.push_str("</div>\n");
    }

    out.push_str(&render_spine(report));
    out.push_str(&render_findings(report));

    out.push_str(&format!(
        "<div class=\"footer\">run {run_id} · {tests} tests run</div>\n",
        run_id = escape(&report.run_id),
        tests = report.summary.total_tests_run,
    ));

    out.push_str("</div>\n");
    out
}

fn render_spine(report: &RunReport) -> String {
    let total: usize = report.summary.by_severity.values().sum();

    let mut bar = String::new();
    let mut legend = String::new();

    // Worst-to-best, matching markdown.rs's `Severity::ALL.iter().rev()`.
    for severity in Severity::ALL.iter().rev() {
        let count = report
            .summary
            .by_severity
            .get(severity)
            .copied()
            .unwrap_or(0);
        let class = severity_class(*severity);
        let label = severity_label(*severity);

        if count > 0 && total > 0 {
            let pct = (count as f64 / total as f64) * 100.0;
            bar.push_str(&format!(
                "<div class=\"seg {class}\" style=\"width:{pct:.2}%\"></div>\n"
            ));
        }

        legend.push_str(&format!(
            "<span class=\"item\"><span class=\"dot {class}\"></span><span class=\"count\">{count}</span> <span class=\"label\">{label}</span></span>\n"
        ));
    }

    format!(
        "<div class=\"spine\">\n<div class=\"spine-bar\">\n{bar}</div>\n<div class=\"spine-legend\">\n{legend}</div>\n</div>\n"
    )
}

fn render_findings(report: &RunReport) -> String {
    let mut out = String::new();
    out.push_str("<div class=\"section-title\">Findings</div>\n");

    let mut findings: Vec<&Finding> = report.findings.iter().filter(|f| !f.suppressed).collect();
    if findings.is_empty() {
        out.push_str("<div class=\"empty\">No findings.</div>\n");
        return out;
    }

    // Worst-first, mirroring the spine and markdown.rs's ordering intent.
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    for finding in findings {
        out.push_str(&render_finding(finding));
    }

    out
}

fn render_finding(finding: &Finding) -> String {
    let class = severity_class(finding.severity);
    let label = severity_label(finding.severity);

    let owasp = if finding.owasp.is_empty() {
        String::new()
    } else {
        format!(
            "<span class=\"owasp\">OWASP: {}</span><br>\n",
            escape(&finding.owasp.join(", "))
        )
    };

    let recommendation = if finding.recommendation.is_empty() {
        String::new()
    } else {
        format!(
            "<div class=\"recommendation\"><span class=\"label\">Recommendation</span>{}</div>\n",
            escape(&finding.recommendation)
        )
    };

    format!(
        r#"<div class="finding" data-severity="{class}">
<div class="finding-head">
<span class="badge">{label}</span>
<span class="finding-title">{title}</span>
</div>
<div class="finding-sub">{scanner} · {test_id} · target: {target_id}</div>
{owasp}<p class="desc">{description}</p>
{evidence}{recommendation}</div>
"#,
        class = class,
        label = label,
        title = escape(&finding.title),
        scanner = escape(&finding.scanner),
        test_id = escape(&finding.test_id),
        target_id = escape(&finding.target_id),
        owasp = owasp,
        description = escape(&finding.description),
        evidence = render_evidence(finding),
        recommendation = recommendation,
    )
}

fn render_evidence(finding: &Finding) -> String {
    let ev = &finding.evidence;
    if ev.request_summary.is_empty() && ev.response_summary.is_empty() {
        return String::new();
    }

    let mut inner = String::new();
    if !ev.request_summary.is_empty() {
        inner.push_str(&format!("<pre>{}</pre>\n", escape(&ev.request_summary)));
    }
    if !ev.response_summary.is_empty() {
        inner.push_str(&format!("<pre>{}</pre>\n", escape(&ev.response_summary)));
    }
    if let Some(assertion) = &ev.matched_assertion {
        inner.push_str(&format!(
            "<pre>matched assertion: {}</pre>\n",
            escape(assertion)
        ));
    }
    if ev.redactions_applied {
        inner.push_str("<pre>[some evidence redacted]</pre>\n");
    }

    format!("<details class=\"evidence\">\n<summary>Evidence</summary>\n{inner}</details>\n")
}

fn severity_class(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
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

/// Minimal HTML-entity escaping for text nodes and attribute values.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsec_core::Evidence;
    use chrono::Utc;
    use std::collections::BTreeMap;

    fn finding(severity: Severity, suppressed: bool) -> Finding {
        Finding {
            id: "f1".to_string(),
            run_id: "run1".to_string(),
            target_id: "target1".to_string(),
            suite_id: "suite1".to_string(),
            test_id: "test-1".to_string(),
            scanner: "prompt_injection".to_string(),
            severity,
            category: "prompt_injection".to_string(),
            title: "Injection <bypass>".to_string(),
            description: "The target leaked & obeyed \"injected\" instructions.".to_string(),
            owasp: vec!["LLM01".to_string()],
            cwe: vec![],
            evidence: Evidence {
                request_summary: "req".to_string(),
                response_summary: "resp".to_string(),
                raw_request_path: None,
                raw_response_path: None,
                trace_id: None,
                matched_assertion: Some("assertion x".to_string()),
                redactions_applied: false,
            },
            recommendation: "Sanitize input.".to_string(),
            references: vec![],
            suppressed,
            suppression_reason: None,
        }
    }

    fn report(findings: Vec<Finding>) -> RunReport {
        let mut by_severity: BTreeMap<Severity, usize> = BTreeMap::new();
        for f in &findings {
            if !f.suppressed {
                *by_severity.entry(f.severity).or_insert(0) += 1;
            }
        }
        let total_findings = findings.iter().filter(|f| !f.suppressed).count();

        RunReport {
            run_id: "run1".to_string(),
            project_name: "demo".to_string(),
            started_at: Utc::now(),
            finished_at: Utc::now(),
            target_ids: vec!["target1".to_string()],
            suite_ids: vec!["suite1".to_string()],
            findings,
            summary: crate::summary::RunSummary {
                total_tests_run: 10,
                total_findings,
                by_severity,
            },
        }
    }

    #[test]
    fn renders_valid_document_shell() {
        let html = to_html(&report(vec![finding(Severity::High, false)]));
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("<html lang=\"en\">"));
        assert!(html.trim_end().ends_with("</html>"));
    }

    #[test]
    fn escapes_finding_text() {
        let html = to_html(&report(vec![finding(Severity::Critical, false)]));
        assert!(!html.contains("Injection <bypass>"));
        assert!(html.contains("Injection &lt;bypass&gt;"));
        assert!(html.contains("&amp;"));
        assert!(html.contains("&quot;injected&quot;"));
    }

    #[test]
    fn suppressed_findings_are_excluded() {
        let html = to_html(&report(vec![finding(Severity::Low, true)]));
        assert!(html.contains("No findings."));
        // The CSS block legitimately contains `data-severity` in its
        // attribute selectors; what must NOT appear is an actual rendered
        // finding card, i.e. the attribute set on a live element.
        assert!(!html.contains("class=\"finding\" data-severity"));
    }

    #[test]
    fn empty_report_shows_no_findings() {
        let html = to_html(&report(vec![]));
        assert!(html.contains("No findings."));
    }

    #[test]
    fn spine_omits_zero_count_segments() {
        let html = to_html(&report(vec![finding(Severity::Critical, false)]));
        // Only one segment should render in the bar (critical); other
        // severities have count 0 and must not produce a <div class="seg ...">.
        let seg_count = html.matches("class=\"seg ").count();
        assert_eq!(seg_count, 1);
        assert!(html.contains("seg critical"));
    }

    #[test]
    fn findings_sorted_worst_first() {
        let html = to_html(&report(vec![
            finding(Severity::Low, false),
            finding(Severity::Critical, false),
        ]));
        let crit_pos = html.find("data-severity=\"critical\"").unwrap();
        let low_pos = html.find("data-severity=\"low\"").unwrap();
        assert!(crit_pos < low_pos);
    }

    #[test]
    fn evidence_included_in_details_block() {
        let html = to_html(&report(vec![finding(Severity::Medium, false)]));
        assert!(html.contains("<details class=\"evidence\">"));
        assert!(html.contains("<pre>req</pre>"));
        assert!(html.contains("<pre>resp</pre>"));
    }
}
