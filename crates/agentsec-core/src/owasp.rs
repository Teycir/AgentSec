/// OWASP LLM Top 10 category mapping.
///
/// Spec section 24: OWASP Mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwaspLlmCategory {
    /// LLM01: Prompt injection.
    PromptInjection,
    /// LLM02: Sensitive information disclosure.
    SensitiveInfoDisclosure,
    /// LLM03: Supply chain.
    SupplyChain,
    /// LLM04: Data/model poisoning.
    DataPoisoning,
    /// LLM05: Improper output handling.
    ImproperOutputHandling,
    /// LLM06: Excessive agency.
    ExcessiveAgency,
    /// LLM07: System prompt leakage.
    SystemPromptLeakage,
    /// LLM08: Vector/embedding weaknesses.
    VectorWeaknesses,
    /// LLM09: Misinformation / grounding failure.
    Misinformation,
    /// LLM10: Unbounded consumption.
    UnboundedConsumption,
}

impl OwaspLlmCategory {
    pub fn code(self) -> &'static str {
        match self {
            OwaspLlmCategory::PromptInjection => "LLM01",
            OwaspLlmCategory::SensitiveInfoDisclosure => "LLM02",
            OwaspLlmCategory::SupplyChain => "LLM03",
            OwaspLlmCategory::DataPoisoning => "LLM04",
            OwaspLlmCategory::ImproperOutputHandling => "LLM05",
            OwaspLlmCategory::ExcessiveAgency => "LLM06",
            OwaspLlmCategory::SystemPromptLeakage => "LLM07",
            OwaspLlmCategory::VectorWeaknesses => "LLM08",
            OwaspLlmCategory::Misinformation => "LLM09",
            OwaspLlmCategory::UnboundedConsumption => "LLM10",
        }
    }
}
