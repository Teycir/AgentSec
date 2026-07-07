//! `agentsec init` (spec 8.2): scaffolds a starter `agentsec.yml`,
//! `.agentsec/` directory, and default `suites/`.

use agentsec_core::ExitCode;

use crate::templates::{
    AGENT_TEMPLATE, DATA_LEAKAGE_BASIC_SUITE, HTTP_CHAT_TEMPLATE, OPENAI_COMPATIBLE_TEMPLATE,
    OUTPUT_HANDLING_BASIC_SUITE, PROMPT_INJECTION_BASIC_SUITE, RAG_TEMPLATE,
    SYSTEM_PROMPT_LEAKAGE_BASIC_SUITE,
};

pub fn run(r#type: String) -> anyhow::Result<ExitCode> {
    let config_yaml = match r#type.as_str() {
        "openai-compatible" => OPENAI_COMPATIBLE_TEMPLATE,
        "rag" => RAG_TEMPLATE,
        "agent" => AGENT_TEMPLATE,
        _ => HTTP_CHAT_TEMPLATE,
    };
    std::fs::write("agentsec.yml", config_yaml)?;
    println!("Created agentsec.yml");

    std::fs::create_dir_all(".agentsec/baselines")?;
    let suppressions_yaml = r#"# agentsec suppressions file
suppressions:
  # - finding_id: "supportbot-api:prompt-injection-basic:untrusted_text_instruction_override"
  #   reason: "Accepted risk for current internal beta"
  #   expires: "2026-09-01"
  #   approved_by: "security@example.com"
"#;
    std::fs::write(".agentsec/suppressions.yml", suppressions_yaml)?;
    println!("Created .agentsec/suppressions.yml");

    std::fs::create_dir_all("suites")?;
    std::fs::write(
        "suites/prompt-injection-basic.yml",
        PROMPT_INJECTION_BASIC_SUITE,
    )?;
    std::fs::write(
        "suites/system-prompt-leakage-basic.yml",
        SYSTEM_PROMPT_LEAKAGE_BASIC_SUITE,
    )?;
    std::fs::write(
        "suites/output-handling-basic.yml",
        OUTPUT_HANDLING_BASIC_SUITE,
    )?;
    std::fs::write("suites/data-leakage-basic.yml", DATA_LEAKAGE_BASIC_SUITE)?;
    println!("Created suites/ directory with default basic suites");

    println!("\nNext steps:");
    println!("  1. Set AGENTSEC_API_KEY");
    println!("  2. Run: agentsec validate");
    println!("  3. Run: agentsec ci");

    Ok(ExitCode::Success)
}
