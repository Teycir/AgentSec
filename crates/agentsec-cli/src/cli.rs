use clap::{Parser, Subcommand};

/// AgentSec Lab — CI/CD-ready security testing for LLM, RAG, and agent apps.
///
/// Spec section 8: CLI Specification.
#[derive(Debug, Parser)]
#[command(name = "agentsec", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Creates a starter agentsec.yml and .agentsec/ directory (spec 8.2).
    Init {
        #[arg(long, default_value = "http-chat")]
        r#type: String,
    },

    /// Validates configuration without running tests (spec 8.3).
    Validate {
        #[arg(long, default_value = "agentsec.yml")]
        config: String,
    },

    /// Primary CI workflow command: runs every configured target/suite
    /// pair and writes reports (spec 8.4).
    Ci {
        #[arg(long, default_value = "agentsec.yml")]
        config: String,
        #[arg(long)]
        out: Option<String>,
        #[arg(long, value_delimiter = ',')]
        format: Option<Vec<String>>,
        #[arg(long)]
        fail_on: Option<String>,
        #[arg(long)]
        baseline: Option<String>,
        #[arg(long)]
        update_baseline: bool,
    },

    /// Ad hoc scan against one target/suite pair (spec 8.5).
    Scan {
        /// Target id declared in agentsec.yml, or a raw URL.
        #[arg(long)]
        target: String,
        #[arg(long)]
        suite: String,
        #[arg(long, default_value = "agentsec.yml")]
        config: String,
        #[arg(long)]
        out: Option<String>,
        #[arg(long, value_delimiter = ',')]
        format: Option<Vec<String>>,
        #[arg(long)]
        fail_on: Option<String>,
        #[arg(long, default_value_t = 120)]
        timeout: u64,
    },

    /// Prints version information.
    Version,

    /// External security-tool plugin adapters (spec 8.8).
    #[command(subcommand)]
    Plugin(PluginCommand),
}

/// Spec 8.8: `agentsec plugin <subcommand>`.
#[derive(Debug, Subcommand)]
pub enum PluginCommand {
    /// Lists known plugin adapters built into this AgentSec binary.
    ///
    /// This is distinct from what's actually installed/runnable on this
    /// machine — use `plugin info <name>` to check whether a given
    /// plugin binary is present on PATH and what it reports for
    /// `capabilities`.
    List,

    /// Shows a plugin's reported capabilities (spec 21.2) by invoking
    /// `<name> capabilities` on PATH.
    Info { name: String },

    /// Runs one suite against one target through a plugin adapter,
    /// writing reports the same way `agentsec scan` does (spec 8.5/8.8).
    Run {
        /// Plugin adapter name, e.g. `promptfoo`.
        name: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        suite: String,
        #[arg(long, default_value = "agentsec.yml")]
        config: String,
        #[arg(long)]
        out: Option<String>,
        #[arg(long, value_delimiter = ',')]
        format: Option<Vec<String>>,
        #[arg(long)]
        fail_on: Option<String>,
        #[arg(long, default_value_t = 120)]
        timeout: u64,
    },

    /// Validates a plugin's scan-output JSON file against the spec 21.4
    /// shape without running anything.
    ValidateOutput {
        /// Path to a plugin scan-output JSON file.
        path: String,
    },
}
