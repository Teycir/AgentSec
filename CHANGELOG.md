# Changelog

All notable changes to AgentSec are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Planned, not yet implemented (moved here from the README's former
Roadmap section):

- Generative adversarial fuzzing: a secondary attacker-LLM mutator loop
  (Ollama/OpenAI) to generate context-specific jailbreak attempts
  dynamically. Ollama is not a current dependency — see the
  [README's Labs section](README.md#-labs-testing-against-live-vulnerable-targets).
- RAG context-poisoning simulator with native mock vector DB connectors.
- Cost and loop-exhaustion protection: monitor tokens, TTFT, and
  recursive execution loops to block model denial-of-service.
- Structured output auditing: validate tool-call parameters for schema
  violations and command injection.
- Interactive CLI TUI dashboard for real-time test-execution progress.
- Provider adapter templates for Gemini, Claude, and Bedrock.
- Local web dashboard/sandbox (offline, axum-powered) for experimenting
  with prompt mitigations.

## [0.1.0] - 2026-07-07

Initial release. Everything below was built in a single continuous
development pass from project scaffolding through the current state of
`master`.

### Added

- Pure Rust CLI workspace (`agentsec-core`, `agentsec-config`,
  `agentsec-scanners`, `agentsec-runner`, `agentsec-report`,
  `agentsec-integrations`, `agentsec-cli`, and a unified `agentsec`
  wrapper crate with optional features).
- CLI entry point and subcommands: `init`, `validate`, `ci`, `scan`,
  `version`, and `plugin` (`list` / `info` / `run` / `validate-output`).
- Built-in scanners: prompt injection, system-prompt leakage, output
  handling, data leakage, RAG (spec 14.3), and agent-tool (spec 14.4),
  the last two closing the scanner gaps left open by ADR-001.
  - `RagScanner` flags instruction-override markers found in *retrieved
    context itself*, independent of whether the model complied.
  - `AgentToolScanner` cross-references `response.tool_calls` against
    `policies.tool_calls.forbidden_tools`, auto-flagging forbidden
    calls even without an explicit suite assertion.
- HTTP execution runner with token/latency limit enforcement and
  configurable concurrency.
- JSON Schema validation and `JsonSchemaMatch` assertion type.
- Report formats: JSON, SARIF, JUnit, Markdown, and a self-contained
  static HTML report (spec 17.5) with a severity "risk spine",
  expandable evidence blocks, OWASP tags, and dark/light theming via
  `prefers-color-scheme`.
- Baseline (`--baseline`) and time-bound suppression (`suppressions.yml`)
  support, keyed on a stable `target:suite:test` finding identity.
- Default network policy: private-network and cloud-metadata-endpoint
  access (including link-local ranges and IPv4-mapped IPv6) is denied
  by default for ad-hoc scans with no `agentsec.yml` present.
- Generic external-tool plugin protocol (spec section 21): a
  subprocess protocol (`capabilities` / `scan` / `scan-output`) for any
  plugin binary on `PATH`, plus a first named adapter for Promptfoo.
- `plugins/promptfoo/`: a real reference plugin binary
  (`agentsec-promptfoo-bridge.js`) that drives an actual
  `promptfoo redteam run` against a live HTTP target via a local
  Ollama provider — no cloud API keys, no mocked fixtures.
- Lab manifests (`labs/*.yml`) describing four publicly available,
  intentionally vulnerable AI agent projects (two `damn-vulnerable-*`
  agents, a RAG poisoning PoC, and DVLA) that can be run locally via
  Docker and scanned against, plus a target-specific demo suite
  (`damn-vulnerable-ai-agent-demo-suite.yml`) for the one lab whose
  built-in canary-based suites need an app-specific canary to detect
  reliably.
- GitHub Actions, GitLab CI, and Jenkins pipeline examples.
- `llms.txt` for AI-agent-optimized repo discoverability.
- README: real terminal recording (VHS) and real HTML report
  screenshots from an actual `agentsec ci` run against a live
  vulnerable target, a documented CI/CD-native workflow demo, and a
  dedicated Labs section clarifying that Docker/Ollama are optional
  and only used by lab targets, never by AgentSec itself.

### Changed

- Refactored `main.rs` (previously a ~1300-line monolith) into
  per-subcommand modules (`commands/{init,validate,ci,scan,plugin}.rs`),
  a shared `pipeline.rs` scan-and-report pipeline, and an extracted,
  independently unit-testable `network_policy.rs`.
- Renamed the project from "AgentSec Lab" to "AgentSec".

### Fixed

- Duplicate `test.id` values within a suite are now rejected at
  validation time, since finding identity (`target:suite:test`) depends
  on uniqueness for baselines and suppressions to work correctly.
- Resource-exhaustion findings (latency/token limit violations) now get
  a real UUID instead of a static composite id, avoiding collisions
  when multiple findings of the same kind occur in one run.
- `clippy::unnecessary_sort_by` in the HTML report's severity ordering
  (only surfaced by CI's exact `--all-features` invocation, not caught
  by a slightly different local check).
- A GitGuardian regex-signature false positive in the output-handling
  scanner.

### Security

- Network policy previously missed link-local ranges
  (`169.254.0.0/16`, the AWS/GCP/Azure cloud-metadata endpoint) and
  IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) — a hostname resolving
  to one of these could have bypassed the private-network gate. Both
  are now explicitly checked, and ad-hoc scans (no config file) default
  to `deny_private_networks=true` with empty `allowed_hosts`.

[Unreleased]: https://github.com/Teycir/AgentSec/commits/master
[0.1.0]: https://github.com/Teycir/AgentSec/commit/d21bed7315538f9336c4a76a14931d19c11ad0fa
