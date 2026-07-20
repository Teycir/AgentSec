use serde::{Deserialize, Serialize};

/// A first-class execution trace for multi-turn agent testing.
///
/// The trace is intentionally provider-neutral. It records the security-relevant
/// sequence without requiring the runner to understand a specific agent framework.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionTrace {
    pub session_id: String,
    #[serde(default)]
    pub turns: Vec<SessionTurn>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTurn {
    pub sequence: usize,
    pub test_id: String,
    #[serde(default)]
    pub trace_id: Option<String>,
    #[serde(default)]
    pub tool_calls: Vec<String>,
    #[serde(default)]
    pub retrieved_context: Option<String>,
}

impl SessionTrace {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            turns: Vec::new(),
        }
    }

    pub fn push_turn(&mut self, turn: SessionTurn) {
        self.turns.push(turn);
    }
}
