use regex::Regex;
use std::sync::OnceLock;

/// A single detected secret-like match, with its span redacted.
#[derive(Debug, Clone)]
pub struct SecretMatch {
    pub kind: &'static str,
    pub redacted_sample: String,
}

struct Detector {
    kind: &'static str,
    regex: &'static str,
}

/// MVP detector set, per spec section 14.6.
const DETECTORS: &[Detector] = &[
    Detector {
        kind: "api_key_generic",
        regex: r"(?i)\b(sk|pk|api|key)-[A-Za-z0-9_\-]{16,}\b",
    },
    Detector {
        kind: "jwt",
        regex: r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
    },
    Detector {
        kind: "aws_access_key",
        regex: r"\bAKIA[0-9A-Z]{16}\b",
    },
    Detector {
        kind: "private_key_block",
        regex: r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    },
    Detector {
        kind: "email",
        regex: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    },
    Detector {
        kind: "phone_number",
        regex: r"\b\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b",
    },
];

static COMPILED: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();

fn compiled() -> &'static Vec<(&'static str, Regex)> {
    COMPILED.get_or_init(|| {
        DETECTORS
            .iter()
            .filter_map(|d| Regex::new(d.regex).ok().map(|re| (d.kind, re)))
            .collect()
    })
}

/// Scans `text` for secret-like patterns, returning redacted matches.
///
/// Spec section 14.6: "The report must redact secret-looking values."
pub fn detect_secrets(text: &str) -> Vec<SecretMatch> {
    let mut found = Vec::new();
    for (kind, re) in compiled() {
        for m in re.find_iter(text) {
            found.push(SecretMatch {
                kind,
                redacted_sample: crate::redact::redact_value(m.as_str()),
            });
        }
    }
    found
}

/// Redacts every detected secret in `text`, replacing each match in place.
pub fn redact_secrets_in_text(text: &str) -> String {
    let mut result = text.to_string();
    for (_, re) in compiled() {
        result = re
            .replace_all(&result, |caps: &regex::Captures| {
                crate::redact::redact_value(&caps[0])
            })
            .to_string();
    }
    result
}

pub const CATEGORY: &str = "data_leakage";

pub struct DataLeakageScanner;

impl crate::Scanner for DataLeakageScanner {
    fn name(&self) -> &'static str {
        CATEGORY
    }

    fn run(
        &self,
        run_id: &str,
        target_id: &str,
        suite: &agentsec_config::Suite,
        response_for: impl Fn(&agentsec_config::SuiteTest) -> crate::response::TargetResponse,
    ) -> Vec<agentsec_core::Finding> {
        suite
            .tests
            .iter()
            .filter(|test| test.category == CATEGORY)
            .filter_map(|test| {
                let response = response_for(test);
                crate::common::evaluate_test(CATEGORY, run_id, target_id, suite, test, &response)
            })
            .collect()
    }
}
