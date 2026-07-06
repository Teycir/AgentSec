use std::collections::HashMap;

/// Headers redacted by default, per spec section 23.1.
pub const DEFAULT_REDACTED_HEADERS: &[&str] = &["authorization", "cookie", "x-api-key"];

/// Redacts sensitive HTTP header values in place, preserving a short
/// visible prefix (like GitHub/Stripe key display conventions) so the
/// value stays recognizable without being usable.
///
/// Spec section 23.1: "Never print full API keys."
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
///
/// `sk-live-1234567890abcdef` -> `sk-live-****************` (spec 14.6 example).
///
/// For long secrets this keeps up to 8 characters visible, matching common
/// key-display conventions (GitHub/Stripe). For short secrets, 8 fixed
/// visible characters could reveal most or all of the value (e.g. a 10-char
/// internal token), so the visible prefix scales down to at most half the
/// value's length.
pub fn redact_value(value: &str) -> String {
    let char_count = value.chars().count();
    let visible = char_count.min(8).min(char_count / 2);
    let prefix: String = value.chars().take(visible).collect();
    let masked_len = char_count.saturating_sub(visible);
    format!("{prefix}{}", "*".repeat(masked_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_secret_keeps_8_char_prefix() {
        let redacted = redact_value("sk-live-1234567890abcdef");
        assert_eq!(redacted, "sk-live-****************");
        assert!(redacted.starts_with("sk-live-"));
    }

    #[test]
    fn short_secret_does_not_reveal_most_of_itself() {
        // A 10-char token: fixed-8 previously left only 2 chars masked.
        let redacted = redact_value("abcdefghij");
        assert_eq!(redacted, "abcde*****");
        let visible_len = redacted.chars().filter(|c| *c != '*').count();
        assert!(visible_len <= redacted.chars().count() / 2);
    }

    #[test]
    fn very_short_secret_is_mostly_masked() {
        let redacted = redact_value("abcd");
        assert_eq!(redacted, "ab**");
    }

    #[test]
    fn empty_value_stays_empty() {
        assert_eq!(redact_value(""), "");
    }

    #[test]
    fn single_char_value_is_fully_masked() {
        assert_eq!(redact_value("a"), "*");
    }
}
