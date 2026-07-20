use std::collections::HashMap;

use regex::Regex;

/// Headers redacted by default, per spec section 23.1.
pub const DEFAULT_REDACTED_HEADERS: &[&str] = &["authorization", "cookie", "x-api-key"];

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

pub fn redact_value(value: &str) -> String {
    let char_count = value.chars().count();
    let visible = char_count.min(8).min(char_count / 2);
    let prefix: String = value.chars().take(visible).collect();
    let masked_len = char_count.saturating_sub(visible);
    format!("{prefix}{}", "*".repeat(masked_len))
}

/// Sanitizes evidence before it can enter findings, logs, or reports.
///
/// This boundary is intentionally applied to summaries rather than raw provider
/// payloads. Raw request/response persistence must be separately controlled by
/// the evidence-retention configuration and must never bypass this sanitizer when
/// material is copied into a Finding.
pub fn sanitize_evidence_text(input: &str) -> String {
    let mut output = input.to_string();

    // Order matters: private-key blocks and bearer tokens should be removed before
    // generic key/value patterns run over the remaining text.
    let patterns = [
        (
            r"-----BEGIN [^-]+ PRIVATE KEY-----[\s\S]*?-----END [^-]+ PRIVATE KEY-----",
            "[REDACTED PRIVATE KEY]",
        ),
        (r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", "$1[REDACTED]"),
        // Plain text: api_key=secret, token: secret, password = secret.
        (
            r"(?i)((?:api[_-]?key|secret|token|password)\s*[:=]\s*)[^\s,;]+",
            "$1[REDACTED]",
        ),
        // JSON-ish forms: "api_key":"secret" and 'token': 'secret'.
        (
            r#"(?i)((?:\"|')?(?:api[_-]?key|secret|token|password)(?:\"|')?\s*:\s*)(?:\"[^\"]*\"|'[^']*'|[^,}\s]+)"#,
            "$1[REDACTED]",
        ),
        (
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            "[REDACTED EMAIL]",
        ),
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

    #[test]
    fn sanitizes_json_secret_shapes() {
        let input = r#"{"api_key":"super-secret","token":"abc123","password": "hunter2"}"#;
        let output = sanitize_evidence_text(input);
        assert!(!output.contains("super-secret"));
        assert!(!output.contains("abc123"));
        assert!(!output.contains("hunter2"));
    }

    #[test]
    fn preserves_non_sensitive_text() {
        let input = "The answer contains a normal sentence and a 200 response.";
        assert_eq!(sanitize_evidence_text(input), input);
    }
}
