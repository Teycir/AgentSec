//! HTML report renderer.

use agentsec_core::{Finding, Severity};

use crate::summary::RunReport;

pub fn to_html(report: &RunReport) -> String {
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>AgentSec Report — {}</title><style>{}</style></head>\n<body>{}</body>\n</html>\n",
        escape(&report.run_id),
        CSS,
        render_body(report)
    )
}

const CSS: &str = r#"
:root { --ink:#E8E6E1; --ink-dim:#9B9890; --surface:#14171C; --surface-2:#1B1F26; --line:#2A2F38; --accent:#E0A75E; --info:#5B7A94; --low:#6E8B5E; --medium:#C9A227; --high:#D0743C; --critical:#C1443C; }
@media (prefers-color-scheme: light) { :root { --ink:#1C1F24; --ink-dim:#5C6068; --surface:#FAF9F7; --surface-2:#F1EEE9; --line:#DEDAD2; } }
* { box-sizing:border-box; } body { margin:0; background:var(--surface); color:var(--ink); font-family:system-ui,sans-serif; line-height:1.5; }
.report { max-width:880px; margin:0 auto; padding:3rem 1.5rem 5rem; } .header { display:flex; justify-content:space-between; align-items:baseline; gap:1rem; border-bottom:1px solid var(--line); padding-bottom:1.25rem; margin-bottom:2rem; flex-wrap:wrap; }
.header h1 { font-size:1.375rem; margin:0; } .header .meta,.targets,.finding-sub,.spine-legend,.section-title,.evidence pre { font-family:ui-monospace,monospace; } .header .meta,.targets { color:var(--ink-dim); font-size:.8125rem; }
.targets { margin-bottom:2rem; } .targets code { color:var(--accent); background:var(--surface-2); padding:.1rem .4rem; border-radius:3px; }
.spine { margin-bottom:2.5rem; } .spine-bar { display:flex; height:10px; border-radius:5px; overflow:hidden; background:var(--surface-2); border:1px solid var(--line); } .seg { height:100%; }
.critical { background:var(--critical); } .high { background:var(--high); } .medium { background:var(--medium); } .low { background:var(--low); } .info { background:var(--info); }
.spine-legend { display:flex; gap:1.5rem; margin-top:.9rem; flex-wrap:wrap; font-size:.8125rem; } .spine-legend .item { display:flex; align-items:baseline; gap:.4rem; } .spine-legend .dot { width:8px; height:8px; border-radius:50%; display:inline-block; } .spine-legend .count { font-weight:600; }
.section-title { font-size:.75rem; text-transform:uppercase; letter-spacing:.08em; color:var(--ink-dim); margin:2.5rem 0 .9rem; } .empty { color:var(--ink-dim); padding:1.5rem 0; }
.finding { border:1px solid var(--line); border-left:3px solid var(--sev-color,var(--info)); background:var(--surface-2); border-radius:6px; padding:1.1rem 1.25rem; margin-bottom:.9rem; } .finding[data-severity=critical]{--sev-color:var(--critical)} .finding[data-severity=high]{--sev-color:var(--high)} .finding[data-severity=medium]{--sev-color:var(--medium)} .finding[data-severity=low]{--sev-color:var(--low)} .finding[data-severity=info]{--sev-color:var(--info)}
.finding-head { display:flex; align-items:baseline; gap:.6rem; flex-wrap:wrap; margin-bottom:.4rem; } .badge { color:var(--sev-color,var(--info)); border:1px solid var(--sev-color,var(--info)); border-radius:3px; padding:.1rem .4rem; font-size:.6875rem; text-transform:uppercase; } .finding-title { font-weight:600; } .finding-sub { font-size:.75rem; color:var(--ink-dim); margin-bottom:.6rem; } .desc { margin:.5rem 0; }
.owasp { display:inline-block; color:var(--accent); margin-bottom:.5rem; } details.evidence { margin-top:.7rem; border-top:1px dashed var(--line); padding-top:.6rem; } details.evidence summary { cursor:pointer; color:var(--ink-dim); } .evidence pre { font-size:.8rem; background:var(--surface); border:1px solid var(--line); border-radius:4px; padding:.75rem; margin:.6rem 0; white-space:pre-wrap; word-break:break-word; } .recommendation { margin-top:.7rem; padding-top:.6rem; border-top:1px solid var(--line); } .recommendation .label { display:block; color:var(--accent); font-size:.7rem; text-transform:uppercase; }
.footer { margin-top:3rem; padding-top:1.25rem; border-top:1px solid var(--line); color:var(--ink-dim); }
"#;

fn render_body(report: &RunReport) -> String {
    let mut out = String::from("<div class=\"report\">\n");
    out.push_str(&format!(
        "<div class=\"header\"><h1>AgentSec Report</h1><div class=\"meta\">{}<br>{}</div></div>\n",
        escape(&report.project_name),
        escape(&report.finished_at.to_rfc3339())
    ));
    if !report.target_ids.is_empty() {
        let targets = report
            .target_ids
            .iter()
            .map(|t| format!("<code>{}</code>", escape(t)))
            .collect::<Vec<_>>()
            .join(" ");
        out.push_str(&format!(
            "<div class=\"targets\">Targets: {targets}</div>\n"
        ));
    }
    out.push_str(&render_spine(report));
    out.push_str(&render_findings(report));
    out.push_str(&format!(
        "<div class=\"footer\">run {} · {} tests run</div>\n</div>\n",
        escape(&report.run_id),
        report.summary.total_tests_run
    ));
    out
}

fn render_spine(report: &RunReport) -> String {
    let total: usize = report.summary.by_severity.values().sum();
    let mut bar = String::new();
    let mut legend = String::new();
    for severity in Severity::ALL.iter().rev() {
        let count = report
            .summary
            .by_severity
            .get(severity)
            .copied()
            .unwrap_or(0);
        let class = severity_class(*severity);
        if count > 0 && total > 0 {
            bar.push_str(&format!(
                "<div class=\"seg {class}\" style=\"width:{:.2}%\"></div>\n",
                count as f64 / total as f64 * 100.0
            ));
        }
        legend.push_str(&format!("<span class=\"item\"><span class=\"dot {class}\"></span><span class=\"count\">{count}</span> <span class=\"label\">{}</span></span>\n", severity_label(*severity)));
    }
    format!("<div class=\"spine\"><div class=\"spine-bar\">{bar}</div><div class=\"spine-legend\">{legend}</div></div>\n")
}

fn render_findings(report: &RunReport) -> String {
    let mut findings: Vec<&Finding> = report.findings.iter().filter(|f| !f.suppressed).collect();
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    if findings.is_empty() {
        return "<div class=\"section-title\">Findings</div>\n<div class=\"empty\">No findings.</div>\n".to_string();
    }
    format!(
        "<div class=\"section-title\">Findings</div>\n{}",
        findings.into_iter().map(render_finding).collect::<String>()
    )
}

fn render_finding(f: &Finding) -> String {
    let owasp = if f.owasp.is_empty() {
        String::new()
    } else {
        format!(
            "<span class=\"owasp\">OWASP: {}</span><br>\n",
            escape(&f.owasp.join(", "))
        )
    };
    let recommendation = if f.recommendation.is_empty() {
        String::new()
    } else {
        format!(
            "<div class=\"recommendation\"><span class=\"label\">Recommendation</span>{}</div>\n",
            escape(&f.recommendation)
        )
    };
    format!("<div class=\"finding\" data-severity=\"{}\">\n<div class=\"finding-head\"><span class=\"badge\">{}</span><span class=\"finding-title\">{}</span></div>\n<div class=\"finding-sub\">{} · {} · target: {}</div>\n{}<p class=\"desc\">{}</p>\n{}{}\n</div>\n", severity_class(f.severity), severity_label(f.severity), escape(&f.title), escape(&f.scanner), escape(&f.test_id), escape(&f.target_id), owasp, escape(&f.description), render_evidence(f), recommendation)
}

fn render_evidence(f: &Finding) -> String {
    let ev = &f.evidence;
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
    format!("<details class=\"evidence\"><summary>Evidence</summary>{inner}</details>\n")
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
            id: "f1".into(),
            run_id: "run1".into(),
            target_id: "target1".into(),
            suite_id: "suite1".into(),
            test_id: "test-1".into(),
            scanner: "prompt_injection".into(),
            severity,
            confidence: 1.0,
            category: "prompt_injection".into(),
            title: "Injection <bypass>".into(),
            description: "The target leaked & obeyed \"injected\" instructions.".into(),
            owasp: vec!["LLM01".into()],
            cwe: vec![],
            evidence: Evidence {
                request_summary: "req".into(),
                response_summary: "resp".into(),
                raw_request_path: None,
                raw_response_path: None,
                trace_id: None,
                matched_assertion: Some("assertion x".into()),
                redactions_applied: false,
            },
            recommendation: "Sanitize input.".into(),
            references: vec![],
            suppressed,
            suppression_reason: None,
        }
    }
    fn report(findings: Vec<Finding>) -> RunReport {
        let mut by_severity = BTreeMap::new();
        for f in &findings {
            if !f.suppressed {
                *by_severity.entry(f.severity).or_insert(0) += 1;
            }
        }
        let total_findings = findings.iter().filter(|f| !f.suppressed).count();
        RunReport {
            run_id: "run1".into(),
            project_name: "demo".into(),
            started_at: Utc::now(),
            finished_at: Utc::now(),
            target_ids: vec!["target1".into()],
            suite_ids: vec!["suite1".into()],
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
        assert!(!html.contains("class=\"finding\" data-severity"));
    }
    #[test]
    fn empty_report_shows_no_findings() {
        assert!(to_html(&report(vec![])).contains("No findings."));
    }
    #[test]
    fn spine_omits_zero_count_segments() {
        let html = to_html(&report(vec![finding(Severity::Critical, false)]));
        assert_eq!(html.matches("class=\"seg ").count(), 1);
        assert!(html.contains("seg critical"));
    }
    #[test]
    fn findings_sorted_worst_first() {
        let html = to_html(&report(vec![
            finding(Severity::Low, false),
            finding(Severity::Critical, false),
        ]));
        assert!(
            html.find("data-severity=\"critical\"").unwrap()
                < html.find("data-severity=\"low\"").unwrap()
        );
    }
    #[test]
    fn evidence_included_in_details_block() {
        let html = to_html(&report(vec![finding(Severity::Medium, false)]));
        assert!(html.contains("<details class=\"evidence\">"));
        assert!(html.contains("<pre>req</pre>"));
        assert!(html.contains("<pre>resp</pre>"));
    }
}
