/// Stable process exit codes, matching spec section 9 exactly.
///
/// These are relied upon by CI/CD pipelines, so values must never change
/// meaning once released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// Success, no findings above threshold.
    Success = 0,
    /// Findings exceeded fail threshold.
    FindingsExceeded = 1,
    /// Invalid configuration.
    InvalidConfig = 2,
    /// Runtime error.
    RuntimeError = 3,
    /// Target unavailable.
    TargetUnavailable = 4,
    /// Authentication error.
    AuthError = 5,
    /// Plugin error.
    PluginError = 6,
    /// Report generation error.
    ReportError = 7,
    /// Policy violation (e.g. destructive scans disabled).
    PolicyViolation = 8,
    /// Baseline or suppression error.
    BaselineError = 9,
    /// Network allowlist violation.
    NetworkViolation = 10,
    /// Interrupted by user (SIGINT).
    Interrupted = 130,
}

impl ExitCode {
    pub fn code(self) -> i32 {
        self as i32
    }
}

impl From<ExitCode> for i32 {
    fn from(value: ExitCode) -> Self {
        value.code()
    }
}
