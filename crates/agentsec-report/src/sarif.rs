use crate::RunReport;
use serde_json::{json, Value};

/// Converts a completed AgentSec run report into a SARIF 2.1.0 JSON representation (spec section 17.2).
pub fn to_sarif(report: &RunReport) -> Value {
    let mut rules = Vec::new();
    let mut rule_ids = std::collections::HashSet::new();

    for finding in &report.findings {
        let rule_id = format!(
            "{}_{}",
            finding.category.to_uppercase(),
            finding.test_id.replace('-', "_").to_uppercase()
        );
        if !rule_ids.contains(&rule_id) {
            rules.push(json!({
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {
                    "text": finding.title
                },
                "fullDescription": {
                    "text": finding.description
                },
                "help": {
                    "text": format!("Recommendation:\n{}\n\nOWASP Categories: {}\n", finding.recommendation, finding.owasp.join(", "))
                }
            }));
            rule_ids.insert(rule_id);
        }
    }

    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|finding| {
            let rule_id = format!(
                "{}_{}",
                finding.category.to_uppercase(),
                finding.test_id.replace('-', "_").to_uppercase()
            );
            let level = match finding.severity {
                agentsec_core::Severity::Critical => "error",
                agentsec_core::Severity::High => "error",
                agentsec_core::Severity::Medium => "warning",
                agentsec_core::Severity::Low => "note",
                agentsec_core::Severity::Info => "note",
            };

            json!({
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": format!("{}: {}", finding.title, finding.description)
                },
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "name": finding.target_id,
                                "kind": "parameter"
                            }
                        ]
                    }
                ]
            })
        })
        .collect();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentSec",
                        "informationUri": "https://github.com/Teycir/AgentSec",
                        "rules": rules
                    }
                },
                "results": results
            }
        ]
    })
}
