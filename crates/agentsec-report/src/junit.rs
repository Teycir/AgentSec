//! JUnit XML report (spec 17.3) — for CI test dashboards.
//!
//! Spec: "Each test case maps to a suite test. Failed assertions become
//! failed test cases." The MVP models one `<testsuite>` per suite_id and
//! one `<testcase>` per finding (a passing test simply produces no finding
//! and therefore no testcase — full pass/fail parity per suite would need
//! the runner to report total test counts, which is out of scope here).

use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::writer::Writer;
use std::collections::BTreeMap;
use std::io::Cursor;

use crate::summary::RunReport;

pub fn to_junit_xml(report: &RunReport) -> anyhow::Result<String> {
    let mut writer = Writer::new_with_indent(Cursor::new(Vec::new()), b' ', 2);

    // Group findings by suite_id so each suite becomes one <testsuite>.
    let mut by_suite: BTreeMap<&str, Vec<&agentsec_core::Finding>> = BTreeMap::new();
    for finding in &report.findings {
        by_suite
            .entry(finding.suite_id.as_str())
            .or_default()
            .push(finding);
    }

    let mut root = BytesStart::new("testsuites");
    root.push_attribute(("name", report.project_name.as_str()));
    writer.write_event(Event::Start(root.clone()))?;

    for (suite_id, findings) in &by_suite {
        let failures = findings.iter().filter(|f| !f.suppressed).count();
        let mut suite = BytesStart::new("testsuite");
        suite.push_attribute(("name", *suite_id));
        suite.push_attribute(("tests", findings.len().to_string().as_str()));
        suite.push_attribute(("failures", failures.to_string().as_str()));
        writer.write_event(Event::Start(suite.clone()))?;

        for finding in findings {
            let mut case = BytesStart::new("testcase");
            case.push_attribute(("name", finding.test_id.as_str()));
            case.push_attribute(("classname", finding.scanner.as_str()));

            if finding.suppressed {
                writer.write_event(Event::Empty(case))?;
                continue;
            }

            writer.write_event(Event::Start(case))?;
            let mut failure = BytesStart::new("failure");
            failure.push_attribute(("message", finding.title.as_str()));
            failure.push_attribute(("type", finding.severity.to_string().as_str()));
            writer.write_event(Event::Start(failure))?;
            writer.write_event(Event::Text(BytesText::new(&finding.description)))?;
            writer.write_event(Event::End(BytesEnd::new("failure")))?;
            writer.write_event(Event::End(BytesEnd::new("testcase")))?;
        }

        writer.write_event(Event::End(BytesEnd::new("testsuite")))?;
    }

    writer.write_event(Event::End(BytesEnd::new("testsuites")))?;

    let bytes = writer.into_inner().into_inner();
    Ok(String::from_utf8(bytes)?)
}
