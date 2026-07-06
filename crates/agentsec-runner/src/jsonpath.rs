use serde_json::Value;

/// Extracts a value at `path` from `root`, using the same simple dotted-path
/// subset (`$.field`, `$.a.b`) as `agentsec_scanners::assertion_eval`, so
/// config-declared response paths behave identically wherever they're used.
///
/// Supports one array-index segment per hop, e.g. `$.choices.0.message.content`.
pub fn extract<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let trimmed = path.trim_start_matches('$').trim_start_matches('.');
    if trimmed.is_empty() {
        return Some(root);
    }

    let mut current = root;
    for segment in trimmed.split('.') {
        current = if let Ok(index) = segment.parse::<usize>() {
            current.get(index)?
        } else {
            current.get(segment)?
        };
    }
    Some(current)
}

/// Convenience wrapper that extracts a string value, falling back to a
/// JSON-stringified form for non-string leaves (numbers, objects, arrays).
pub fn extract_string(root: &Value, path: &str) -> Option<String> {
    extract(root, path).map(|v| match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    })
}

/// Extracts a list of strings from an array at `path` (used for citations
/// and tool-call lists).
pub fn extract_string_list(root: &Value, path: &str) -> Vec<String> {
    match extract(root, path) {
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_nested_field() {
        let root = json!({"choices": [{"message": {"content": "hi"}}]});
        assert_eq!(
            extract_string(&root, "$.choices.0.message.content"),
            Some("hi".to_string())
        );
    }

    #[test]
    fn missing_path_returns_none() {
        let root = json!({"a": 1});
        assert_eq!(extract_string(&root, "$.b"), None);
    }

    #[test]
    fn extracts_string_list() {
        let root = json!({"citations": ["https://a", "https://b"]});
        assert_eq!(
            extract_string_list(&root, "$.citations"),
            vec!["https://a".to_string(), "https://b".to_string()]
        );
    }
}
