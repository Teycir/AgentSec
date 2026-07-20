use std::collections::HashMap;

use regex::Regex;

/// Headers redacted by default, per spec section 23.1.
pub const DEFAULT_REDACTED_HEADERS: &[&str] = &["authorization", "cookie", "x-api-key"];

/// Redacts sensitive HTTP header values in place, preserving a short
/// visible prefix so the value stays recognizable without being usable.
pub fn redact_headers(
    headers: &HashMap<String, String>,
    extra: &[String],
) -> HashMap<String, String> {
    let mut redacted_names: Vec<String> = DEFAULT_REDACTED_HEADERS
        .iter()
        .map(|s| s.to_lowercase())
        .collect();
    redacted_names.extend(extra.iter().map(|s| s.to_lowercase()));

    headers
        .iter()
        .map(|(k, v)| {
            if redacted_names.contains(&k.to_lowercase()) {
                (k.clone(), redact_value(v))
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}

/// Redacts a single string value, keeping a short prefix visible.
pub fn redact_value(value: &str) -> String {
    let char_count = value.chars().count();
    let visible = char_count.min(8).min(char_count / 2);
    let prefix: String = value.chars().take(visible).collect();
    let masked_len = char_count.saturating_sub(visible);
    format!("{prefix}{}", "*".repeat(masked_len))
}

/// Sanitizes evidence before it can enter findings, logs, or reports.
///
/// This is deliberately conservative: it redacts bearer tokens, common API-key
/// assignments, private-key blocks, and email addresses. It is not a substitute
/// for provider-specific secret detection, but establishes a single safe boundary
/// for evidence emitted by the scanner.
pub fn sanitize_evidence_text(input: &str) -> String {
    let mut output = input.to_string();

    let patterns = [
        (r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", "$1[REDACTED]"),
        (r"(?i)((?:api[_-]?key|secret|token|password)\s*[:=]\s*)[^\s,;]+", "$1[REDACTED]"),
        (r"-----BEGIN [^-]+ PRIVATE KEY-----[\s\S]*?-----END [^-]+ PRIVATE KEY-----", "[REDACTED PRIVATE KEY]"),
        (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[REDACTED EMAIL]"),
    ];

    for (pattern, replacement) in patterns {
        if let Ok(regex) = Regex::new(pattern) {
            output = regex.replace_all(&output, replacement).into_owned();
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_common_secret_and_pii_shapes() {
        let input = "Authorization: Bearer abc.def.ghi api_key=secret123 user@example.com";
        let output = sanitize_evidence_text(input);
        assert!(!output.contains("abc.def.ghi"));
        assert!(!output.contains("secret123"));
        assert!(!output.contains("user@example.com"));
    }
}
