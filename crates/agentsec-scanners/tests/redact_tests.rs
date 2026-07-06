use agentsec_scanners::redact::redact_value;

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
