use agentsec_config::Assertion;
use agentsec_scanners::assertion_eval::evaluate;
use agentsec_scanners::TargetResponse;

const SCHEMA: &str = r#"{
    "type": "object",
    "required": ["status", "code"],
    "properties": {
        "status": { "type": "string" },
        "code": { "type": "number" },
        "tags": {
            "type": "array",
            "items": { "type": "string" }
        }
    }
}"#;

fn response_with_answer(answer: &str) -> TargetResponse {
    TargetResponse {
        answer: answer.to_string(),
        ..Default::default()
    }
}

fn schema_assertion() -> Assertion {
    Assertion::JsonSchemaMatch {
        schema: SCHEMA.to_string(),
    }
}

#[test]
fn valid_json_passes_schema_match() {
    let response =
        response_with_answer(r#"{"status": "success", "code": 200, "tags": ["prod", "v1"]}"#);
    let result = evaluate(&schema_assertion(), &response);
    assert!(result.passed);
}

#[test]
fn missing_required_property_fails() {
    let response = response_with_answer(r#"{"status": "success"}"#);
    let result = evaluate(&schema_assertion(), &response);
    assert!(!result.passed);
    assert!(result
        .description
        .contains("missing required property 'code'"));
}

#[test]
fn wrong_property_type_fails() {
    let response = response_with_answer(r#"{"status": "success", "code": "200"}"#);
    let result = evaluate(&schema_assertion(), &response);
    assert!(!result.passed);
    assert!(result
        .description
        .contains("property 'code': expected a number"));
}

#[test]
fn malformed_json_fails() {
    let response = response_with_answer(r#"{"status": "#);
    let result = evaluate(&schema_assertion(), &response);
    assert!(!result.passed);
    assert!(result.description.contains("response is not valid JSON"));
}
