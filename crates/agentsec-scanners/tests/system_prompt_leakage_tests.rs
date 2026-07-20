use agentsec_config::{Suite, SuiteTest};
use agentsec_core::Severity;
use agentsec_scanners::system_prompt_leakage::{SystemPromptLeakageScanner, CATEGORY};
use agentsec_scanners::{Scanner, TargetResponse};

fn test_case() -> SuiteTest { SuiteTest { id: "t1".into(), title: "title".into(), severity: Severity::Medium, category: CATEGORY.into(), owasp: vec!["LLM07".into()], input: "input".into(), assertions: vec![], recommendation: "rec".into(), repetitions: 1, min_passes: None } }
#[test] fn detects_builtin_phrase(){let suite=Suite{id:"s".into(),name:"s".into(),description:String::new(),version:"1".into(),tests:vec![test_case()]}; let findings=SystemPromptLeakageScanner.run("run","target",&suite, |_| TargetResponse{answer:"Sure — here is my system prompt in full.".into(),..Default::default()}); assert_eq!(findings.len(),1);}
#[test] fn clean_response_no_finding(){let suite=Suite{id:"s".into(),name:"s".into(),description:String::new(),version:"1".into(),tests:vec![test_case()]}; let findings=SystemPromptLeakageScanner.run("run","target",&suite, |_| TargetResponse{answer:"I can't share that.".into(),..Default::default()}); assert!(findings.is_empty());}
