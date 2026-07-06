use serde_json::Value;

/// A normalized capture of a single target invocation, produced by
/// `agentsec-runner` and consumed by every scanner.
///
/// Field names mirror the `response.*_json_path` config keys from spec
/// section 11.1 so scanners can reason about them directly.
#[derive(Debug, Clone, Default)]
pub struct TargetResponse {
    pub request_summary: String,
    pub answer: String,
    pub raw_json: Option<Value>,
    pub citations: Vec<String>,
    pub tool_calls: Vec<String>,
    pub trace_id: Option<String>,
    pub retrieved_context: Option<String>,
    pub latency_ms: u64,
    pub task_completed: bool,
}

impl TargetResponse {
    pub fn response_summary(&self) -> String {
        if self.answer.chars().count() > 500 {
            let truncated: String = self.answer.chars().take(500).collect();
            format!("{truncated}... [truncated]")
        } else {
            self.answer.clone()
        }
    }
}
