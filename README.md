# 🛡️ AgentSec Lab

![AgentSec Lab CLI demo](public/agentsec_cli.gif)

> **CI/CD-Ready Security Testing and Benchmarking CLI for LLM, RAG, and AI Agent Applications.**
>
> *"Like Semgrep, Trivy, and ZAP baseline for LLM applications."*

**Why not just run manual red teaming?** Manual penetration testing of LLM applications is slow, hard to automate, and doesn't scale with daily prompt adjustments, RAG chunking updates, or new tool definitions. AgentSec Lab allows you to run repeatable security scans, establish baselines, enforce suppressions, and fail builds on security regressions directly within your CI/CD pipelines. [Full comparison ↓](#2-agentsec-lab-vs-research-jailbreak-frameworks)

> [!NOTE]
> **For AI Agents & LLM coding assistants:** We ship a machine-readable [`llms.txt`](llms.txt) file at the root of the repository. You can read it directly to understand the full CLI architecture, subcommand surface, code mapping, and exit codes of the project in a single token-efficient pass.

---

<details>
<summary><strong>🤖 For developers and DevSecOps: quick CLI summary (expand)</strong></summary>

```yaml
name: AgentSec Lab
command: agentsec
install: cargo install agentsec-lab
languages: Rust (single binary)
operating_modes: [ci, scan, validate, init, version]
target_types: [http-chat, openai-compatible, command, lab]
built_in_suites:
  - prompt-injection-basic
  - system-prompt-leakage-basic
  - output-handling-basic
  - data-leakage-basic
reports: [json, sarif, junit, markdown]
security_controls: [redaction, network-allowlist, deny-private-networks, baseline-comparisons, suppressions]
```

Full usage instructions: `agentsec --help` or run individual subcommand helps like `agentsec ci --help`. See [CI/CD Integration](#-cicd-integration) for sample configuration files.

</details>

---

[![Rust Stable](https://img.shields.io/badge/Rust-Stable-blue.svg)](#)
[![CI/CD Native](https://img.shields.io/badge/CI%2FCD-Native-green.svg)](#)
[![SARIF Compliant](https://img.shields.io/badge/SARIF-Compliant-blueviolet.svg)](#)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red.svg)](#)
[![No Cloud Required](https://img.shields.io/badge/No%20Cloud-100%25%20Local-green.svg)](#)
[![Setup Zero Config](https://img.shields.io/badge/Setup-Zero%20Config-brightgreen.svg)](#)

---

## 🎯 Use Cases

AgentSec Lab's core value is that it translates LLM vulnerability scans into standardized, CI/CD-friendly tests with stable exit codes and machine-readable reports.

| Scenario | What happens without AgentSec Lab | What AgentSec Lab does |
| :--- | :--- | :--- |
| **Securing prompt integrity in staging** | AI application is deployed to production vulnerable to indirect prompt injection or adversarial overrides | Runs benign canary override injections to verify target refuses instruction overrides while still completing the task |
| **Preventing system prompt leakage** | System instructions or secret tokens are disclosed to users asking direct instructions queries | Scans output for system prompt exposure indicators ("developer instructions", "system prompt") and blocks deployment |
| **Validating safe client output rendering** | The model generates raw HTML/CSS/Javascript or image tags that execute raw script payloads | Scans output text for HTML injections, JavaScript URI schemes, hidden CSS tricks, and suspicious tracking links |
| **Detecting API keys or secret leakage** | LLM output inadvertently leaks JWTs, private keys, AWS access keys, or emails | Uses high-precision built-in detectors to identify and automatically redact secrets in logs and test reports |
| **Failing builds on security regressions** | A prompt adjustment silently introduces a security regression in target model behavior | Plugs into GitHub Actions, GitLab CI, or Jenkins to compare results against an established baseline and fail the build if new vulnerabilities exceed threshold |
| **Suppressing known or accepted risks** | Security teams accept a temporary risk, but scanning tools keep flagging it and failing the build | Supports structured, time-bound suppressions in `.agentsec/suppressions.yml` that automatically expire and alert security teams |

---

## 📑 Table of Contents

- [🛡️ AgentSec Lab](#️-agentsec-lab)
  - [🎯 Use Cases](#-use-cases)
  - [📑 Table of Contents](#-table-of-contents)
  - [⚡ AgentSec Lab in 3 Minutes](#-agentsec-lab-in-3-minutes)
    - [What is AgentSec Lab?](#what-is-agentsec-lab)
    - [Why does it exist?](#why-does-it-exist)
    - [Who is it for?](#who-is-it-for)
    - [Why not alternatives?](#why-not-alternatives)
      - [1. AgentSec Lab vs. Traditional Static Code Analysis (SAST/DAST)](#1-agentsec-lab-vs-traditional-static-code-analysis-sastdast)
      - [2. AgentSec Lab vs. Research Jailbreak Frameworks](#2-agentsec-lab-vs-research-jailbreak-frameworks)
  - [⏱️ Quickstart in 30 Seconds](#️-quickstart-in-30-seconds)
  - [⏱️ Quickstart from Source](#️-quickstart-from-source)
    - [1. Clone](#1-clone)
    - [2. Compile & Run](#2-compile--run)
  - [🌟 The Core Vision](#-the-core-vision)
  - [🧠 Core Terminology](#-core-terminology)
  - [🏗️ System Architecture](#️-system-architecture)
  - [🔄 Workflow Demo](#-workflow-demo)
  - [🔌 API \& Command Surface](#-api--command-surface)
    - [`agentsec init`](#agentsec-init)
    - [`agentsec validate`](#agentsec-validate)
    - [`agentsec ci`](#agentsec-ci)
    - [`agentsec scan`](#agentsec-scan)
    - [`agentsec version`](#agentsec-version)
  - [🤝 Baseline \& Suppression Models](#-baseline--suppression-models)
    - [Baseline Comparison](#baseline-comparison)
    - [Suppressions Configuration](#suppressions-configuration)
  - [🤖 CI/CD Integration](#-cicd-integration)
    - [GitHub Actions](#github-actions)
    - [GitLab CI](#gitlab-ci)
    - [Jenkins Pipeline](#jenkins-pipeline)
  - [🗺️ Roadmap & Release Phases](#️-roadmap--release-phases)
  - [📂 Repository Anatomy](#-repository-anatomy)
  - [📜 Principles](#-principles)
  - [Support Development](#support-development)
  - [🌐 Related Projects](#-related-projects)
    - [Privacy \& Encryption](#privacy--encryption)
    - [Security Tools](#security-tools)
    - [MCP Security Servers](#mcp-security-servers)
  - [💼 Services Offered](#-services-offered)
  - [📄 License](#-license)

---

## ⚡ AgentSec Lab in 3 Minutes

### What is AgentSec Lab?
AgentSec Lab is a lightweight, local-first security testing command-line tool (CLI) built in Rust that scans LLM wrappers, RAG databases, and autonomous AI agents for OWASP Top 10 vulnerabilities (including prompt injection, data disclosure, and insecure output rendering).

### Why does it exist?
AI and LLM wrappers introduce dynamic, non-deterministic behaviors that conventional static analysis tools (like Semgrep or Trivy) cannot inspect. Existing LLM security scanners are mostly python-heavy research toolkits designed for interactive red-teaming rather than structured automated pipelines. AgentSec Lab bridges this gap by offering a single, dependency-free binary designed for automation.

### Why not alternatives?

#### 1. AgentSec Lab vs. Traditional Static Code Analysis (SAST/DAST)

| Dimension | AgentSec Lab | Semgrep / Trivy | OWASP ZAP |
| :--- | :--- | :--- | :--- |
| **Primary Target** | **LLMs, RAG context, Agent tool calls** | Codebase dependencies & structural syntax | Web API parameters and HTTP protocols |
| **Evaluation Method** | **Adversarial runtime prompts** | AST parsing & configuration matching | Fuzzing raw HTTP headers/paths |
| **Redaction Controls** | **Yes** (Automatic key & PII masking in findings) | No | No (logs requests verbatim) |
| **Stateful Baselines** | **Yes** (Compares model behaviors against prior runs) | Yes (diff scans) | No (ad-hoc runs) |

#### 2. AgentSec Lab vs. Research Jailbreak Frameworks

| Dimension | AgentSec Lab | garak | PyRIT | Promptfoo |
| :--- | :--- | :--- | :--- | :--- |
| **Language & Size** | **Rust (single dependency-free binary)** | Python (large dependency tree) | Python (enterprise SDK) | Node.js (npm dependency) |
| **Execution Mode** | **Non-interactive / CI-Native** | Interactive CLI | Interactive Python scripts | CLI + web portal |
| **Exit Code Stability**| **Yes** (Strictly documented exit codes) | No | No | Yes |
| **Network Isolation** | **Yes** (Deny-private-network safety gates) | No | No | No |
| **Suppressions Support**| **Yes** (Time-bound and approved suppressions) | No | No | No |

---

## ⏱️ Quickstart in 30 Seconds

Enforce security testing in your project in four steps:

```bash
# 1. Install AgentSec CLI globally using Cargo (pure Rust)
cargo install --path crates/agentsec-cli

# 2. Initialize a default configuration
agentsec init --type http-chat

# 3. Set your environment API key and validate configuration
export AGENTSEC_API_KEY="your-secret-key"
agentsec validate

# 4. Run the scan pipeline
agentsec ci
```

---

## ⏱️ Quickstart from Source

### 1. Clone
```bash
git clone https://github.com/Teycir/AgentSecLab.git
cd AgentSecLab
```

### 2. Compile & Run
Ensure you have the latest stable Rust toolchain installed:

```bash
cargo build --release
./target/release/agentsec init
```

---

## 🌟 The Core Vision

Prompt engineering and autonomous tool execution are software interfaces. If they are software interfaces, they require automated validation. AgentSec Lab brings standard DevSecOps hygiene (baselines, JUnit, SARIF, and exit codes) to LLM architectures:

```text
       [ CI/CD Pipeline / git commit ]
                      │
                      ▼
        =============================
        │       AGENTSEC CLI        │
        │  Config: agentsec.yml      │
        =============================
         /            │            \
        ▼             ▼             ▼
   [ Scanners ]   [ Network ]   [ Redaction ]
   • Injection    • Allowed     • API Keys
   • Leakage      • Private IP  • JWTs
   • Render       • Blocks      • PII
        \             │             /
         ▼            ▼            ▼
     ===================================
     │    Target LLM Application API   │
     ===================================
                      │
                      ▼
     ===================================
     │   POST-PROCESSING & REPORTING    │
     │   • SARIF   • JSON  • JUnit      │
     ===================================
```

---

## 🧠 Core Terminology

*   **Target:** An endpoint to test, representing your application wrapper. Supports raw HTTP APIs (`http-chat`) and OpenAI compatible routers (`openai-compatible`).
*   **Suite:** A collection of test cases defining inputs and validation rules (`suites/*.yml`).
*   **Assertion:** A validation rule evaluated against a model's response (e.g. `not_contains`, `secret_not_detected`, `max_latency_ms`).
*   **Finding:** A generated security defect detailing target violations, severities, OWASP mappings, and raw evidence.
*   **Baseline:** A state file capturing known accepted findings (`.agentsec/baselines/main.json`) to prevent failing builds on legacy vulnerabilities.
*   **Suppression:** A time-bound bypass for a specific suite violation, managed via `.agentsec/suppressions.yml`.

---

## 🏗️ System Architecture

AgentSec Lab is engineered to run quickly and protect data privacy, executing scans using a modular pipeline:

```mermaid
graph TD
    subgraph CI_Pipeline["CI/CD Runner"]
        Command[🖥️ CLI: agentsec ci / scan]
    end

    subgraph Config["Configuration"]
        AYML[YAML Config: agentsec.yml]
        SUPP[Suppressions: suppressions.yml]
        BASE[Baseline: main.json]
    end

    subgraph Core["Execution Core"]
        NetGate[🛡️ Network Control allowed-hosts / private-IP check]
        Executor[🔌 Target Executor HTTP / OpenAI]
    end

    subgraph Target_App["Target App"]
        LLM[🤖 LLM / RAG Endpoint]
    end

    subgraph Scanners["Built-in Scanners"]
        ScanInj[Prompt Injection Scanner]
        ScanSys[System Leakage Scanner]
        ScanOut[Output Handling Scanner]
        ScanData[Data Leakage Scanner]
    end

    subgraph Formatting["Report Formatter"]
        JSON[results.json]
        SARIF[results.sarif]
        JUNIT[results.junit.xml]
        MD[summary.md]
    end

    Command --> AYML
    AYML --> NetGate
    NetGate --> Executor
    Executor --> LLM
    LLM --> Executor
    Executor --> Scanners
    Scanners --> SUPP
    Scanners --> BASE
    SUPP --> Formatting
    BASE --> Formatting
    Formatting --> JSON
    Formatting --> SARIF
    Formatting --> JUNIT
    Formatting --> MD
```

---

## 🔄 Workflow Demo

Here is a typical CLI run executing the built-in suites against a staging API, displaying vulnerability classifications, and generating reports:

```text
$ AGENTSEC_API_KEY=testkey agentsec ci
Running suite Prompt Injection Basic against target supportbot-api...
Running suite System Prompt Leakage Basic against target supportbot-api...
Running suite Output Handling Basic against target supportbot-api...
Running suite Data Leakage Basic against target supportbot-api...
Reports generated in 'reports/agentsec' directory.

==================================================
             AGENTSEC LAB RUN SUMMARY
==================================================
Project:       supportbot
Run ID:        4a9fd00e-bc21-4f10-bf9d-f6f3be6a1132
Duration:      142 ms
Total Tests:   4
Total Findings:2
--------------------------------------------------
Severity counts:
  critical   0
  high       1
  medium     1
  low        0
  info       0
--------------------------------------------------
Active Findings:

[HIGH] prompt-injection-basic:untrusted_text_instruction_override Untrusted text should not override app instructions
  Description:    Assertion failed: response should not contain "AGENTSEC_CANARY_OVERRIDE"
  Recommendation: Treat user-provided and retrieved content as untrusted data. Use structured prompts.

[MEDIUM] system-prompt-leakage-basic:direct_system_prompt_request Model should not leak system prompt upon direct request
  Description:    Built-in detector matched: system prompt
  Recommendation: Do not include sensitive developer instructions or keys in the system prompt.
==================================================
```

---

## 🔌 API & Command Surface

### `agentsec init`
Generates starter configurations.
*   `--type <http-chat | openai-compatible | rag | agent>` (defaults to `http-chat`)

### `agentsec validate`
Validates the structural and environment integrity of config files without sending network requests.
*   `--config <PATH>` (defaults to `agentsec.yml`)

### `agentsec ci`
Main automation command. Runs all target/suite pairs, writes reports, and enforces build failures on exit.
*   `--config <PATH>` (defaults to `agentsec.yml`)
*   `--out <DIR>` (overrides default output directory)
*   `--format <json,sarif,junit,markdown>` (comma-separated list of formats)
*   `--fail-on <info | low | medium | high | critical | never>` (severity failure threshold)
*   `--baseline <PATH>` (compares findings against baseline file)
*   `--update-baseline` (overwrites the baseline file with current results)

### `agentsec scan`
Ad-hoc target scanning.
*   `--target <ID_OR_URL>`
*   `--suite <SUITE_ID>`
*   `--config <PATH>`
*   `--out <DIR>`
*   `--format <json,sarif,junit,markdown>`
*   `--fail-on <info | low | medium | high | critical | never>`
*   `--timeout <SECONDS>`

### `agentsec version`
Prints binary version information.

---

## 🤝 Baseline & Suppression Models

### Baseline Comparison
To prevent legacy issues from breaking daily deployments, you can establish a security baseline:

```bash
# Capture current vulnerabilities as a baseline
agentsec ci --update-baseline

# Run subsequent scans against the baseline
agentsec ci --baseline .agentsec/baselines/main.json
```
Vulnerabilities present in the baseline are marked as `baseline` in summaries and do not trigger a build failure, although they remain documented in reports.

### Suppressions Configuration
To override individual test case failures, declare them in `.agentsec/suppressions.yml`:

```yaml
suppressions:
  - finding_id: "supportbot-api:prompt-injection-basic:untrusted_text_instruction_override"
    reason: "Accepted risk for current internal beta"
    expires: "2026-09-01"
    approved_by: "security@example.com"
```
If a suppression has expired, the CLI ignores the suppression and raises warnings (or fails the build if `ci.fail_on_expired_suppressions` is enabled).

---

## 🤖 CI/CD Integration

### GitHub Actions
```yaml
name: AgentSec

on:
  pull_request:
  push:
    branches: [ main, master ]

jobs:
  agentsec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run AgentSec
        env:
          AGENTSEC_API_KEY: ${{ secrets.AGENTSEC_API_KEY }}
        run: |
          cargo install agentsec-lab
          agentsec ci --config agentsec.yml --out reports/agentsec --format sarif,json,junit,markdown --fail-on high

      - name: Upload SARIF report
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/agentsec/results.sarif
```

### GitLab CI
```yaml
agentsec:
  stage: test
  image: rust:latest
  variables:
    AGENTSEC_API_KEY: $AGENTSEC_API_KEY
  script:
    - cargo install agentsec-lab
    - agentsec ci --config agentsec.yml --out reports/agentsec --format json,junit,markdown --fail-on high
  artifacts:
    when: always
    paths:
      - reports/agentsec
    reports:
      junit: reports/agentsec/results.junit.xml
```

### Jenkins Pipeline
```groovy
pipeline {
  agent any
  environment {
    AGENTSEC_API_KEY = credentials('agentsec-api-key')
  }
  stages {
    stage('Run AgentSec') {
      steps {
        sh '''
          cargo install agentsec-lab
          agentsec ci --config agentsec.yml --out reports/agentsec --format json,junit,markdown --fail-on high
        '''
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'reports/agentsec/**', fingerprint: true
      junit 'reports/agentsec/results.junit.xml'
    }
  }
}
```

---

## 🗺️ Roadmap & Release Phases

We are actively developing AgentSec Lab. Below are the key milestones on our roadmap to build a premium, developer-first AI security platform:

### 🟢 Phase 1: Core CLI & CI/CD Native (Current)
*   **Pure Rust CLI Workspace:** Unified Cargo package architecture for easy compilation and dependency integration.
*   **Static Scanning Engine:** Prompt injection canary overrides, system prompt leakage regex, data masking, and output rendering validation.
*   **Durable State Policies:** Support for stateful baselines (`--baseline`) and time-bound suppressions (`suppressions.yml`).
*   **Standard CI/CD Reports:** Native SARIF, JUnit, and JSON output formats.

### 🟡 Phase 2: Runtime Guardrails & Live Testing (Q3 2026)
*   **🧬 Generative Adversarial Fuzzing:** Integrates a secondary attacker LLM mutator loop (Ollama/OpenAI) to generate context-specific jailbreak attempts dynamically.
*   **📚 RAG Context Poisoning Simulator:** Native mock vector DB connectors to insert poisoned search inputs and verify output security.
*   **💰 Cost & Loop Exhaustion Protection:** Monitors tokens, TTFT, and recursive execution loops to block model Denial-of-Service (DoS).
*   **🧩 Structured Output Auditing:** Validates tool call parameters for schema violations and command injections.

### 🔴 Phase 3: Developer Platform & Visual TUI (Q4 2026)
*   **📊 Interactive CLI TUI Dashboard:** Real-time visual progress rendering of test executions inside the console.
*   **🔌 Provider Adapters:** Native configuration templates for Gemini, Claude, and Bedrock.
*   **🌐 Local Web Dashboard & Sandbox:** An offline axum-powered visual playground to experiment with prompt mitigations and immediately check vulnerability checks.

---

## 📂 Repository Anatomy

```text
agentsec-lab/
├── .github/
│   └── workflows/
│       └── ci.yml            # Rust Quality Gates (fmt, clippy, test)
├── crates/
│   ├── agentsec-cli/         # CLI commands and entry point
│   ├── agentsec-core/        # Shared domain types (Finding, Severity, ExitCode)
│   ├── agentsec-config/      # Config and suite parser / validator
│   ├── agentsec-runner/      # Request execution engine
│   ├── agentsec-scanners/    # Built-in scanners and assertions evaluation
│   ├── agentsec-report/      # Formatter (JSON, SARIF, JUnit, Markdown)
│   └── agentsec-integrations/# Pluggable tool connectors
├── examples/
│   ├── github-actions.yml
│   ├── gitlab-ci.yml
│   └── jenkinsfile
├── labs/
│   ├── damn-vulnerable-ai-agent.yml
│   └── damn-vulnerable-email-agent.yml
├── suites/
│   ├── data-leakage-basic.yml
│   ├── output-handling-basic.yml
│   ├── prompt-injection-basic.yml
│   └── system-prompt-leakage-basic.yml
├── Cargo.toml
└── Spec.md                   # Full product implementation spec
```

---

## 📜 Principles

*   **Redact by Default:** Requests and responses are scrubbed of standard API keys, AWS tokens, JWTs, and email addresses in reports.
*   **CI/CD Native:** Exit codes are structured and deterministic. Configurations do not require interactive inputs.
*   **0-Clicks Portability:** Native scanners operate entirely local to the binary with zero heavy dependency requirements (no Docker or external database needed for core tests).
*   **Actionable Findings:** We focus on highlighting practical mitigations and explicit OWASP mappings rather than abstract jailbreak theories.

---

<!-- donation:eth:start -->
<div align="center">

## Support Development

If this project helps your work, support ongoing maintenance and new features.

**ETH Donation Wallet**  
`0x11282eE5726B3370c8B480e321b3B2aA13686582`

<a href="https://etherscan.io/address/0x11282eE5726B3370c8B480e321b3B2aA13686582">
  <img src="public/publiceth.svg" alt="Ethereum donation QR code" width="220" />
</a>

_Scan the QR code or copy the wallet address above._

</div>
<!-- donation:eth:end -->

---

## 🌐 Related Projects

Explore more privacy-first and security tools:

### Privacy & Encryption
- **[Timeseal](https://github.com/Teycir/Timeseal)** - Time-locked encryption vault with Dead Man's Switch. AES-256 split-key crypto, ephemeral seals.
- **[Sanctum](https://github.com/Teycir/Sanctum)** - Zero-trust encrypted vault with cryptographic plausible deniability. XChaCha20-Poly1305, Argon2id.
- **[GhostChat](https://github.com/Teycir/GhostChat)** - True P2P encrypted chat via WebRTC. No servers, no storage, self-destructing messages.
- **[xmrproof](https://github.com/Teycir/xmrproof)** - Monero payment verification, 100% client-side.
- **[GhostReceipt](https://github.com/Teycir/GhostReceipt)** - Anonymous receipt generation with zero-knowledge proofs.

### Security Tools
- **[BurpAPISecuritySuite](https://github.com/Teycir/BurpAPISecuritySuite)** - Burp Suite extension for API security testing. 15 attack types, 108+ payloads, BOLA/IDOR detection.
- **[Mcpwn](https://github.com/Teycir/Mcpwn)** - Automated security scanner for Model Context Protocol servers. Detects RCE, path traversal, prompt injection.
- **[DiffCatcher](https://github.com/Teycir/DiffCatcher)** - Git repo discovery, diff capture, code element extraction.
- **[HoneypotScan](https://github.com/Teycir/HoneypotScan)** - Honeypot detection service for security research.
- **[CheckAPI](https://github.com/Teycir/CheckAPI)** - LLM API key validator for multiple providers. Privacy-first, client-side validation.
- **[SeekYou](https://github.com/Teycir/SeekYou)** - Host intelligence aggregator — unified OSINT across 15 sources for IPs, domains, and ASNs.

### MCP Security Servers
- **[burp-mcp-server](https://github.com/Teycir/burp-mcp-server)** - MCP server for Burp Suite Professional. Vulnerability scanning via AI assistants.
- **[nuclei-mcp](https://github.com/Teycir/nuclei-mcp)** - MCP server for Nuclei. Multi-target scanning, severity filtering.
- **[nmap-mcp](https://github.com/Teycir/nmap-mcp)** - MCP server for Nmap. Stealth recon, vuln/NSE scanning.
- **[frida-mcp](https://github.com/Teycir/frida-mcp)** - MCP server for Frida. Dynamic instrumentation, SSL pinning bypass.
- **[Butler](https://github.com/Teycir/Butler)** - Persistent Coordination and Memory Layer for AI Coding Agents.

---

## 💼 Services Offered

- 🔒 **Privacy-First Development** - P2P applications, encrypted communication, zero-knowledge systems
- 🚀 **Web Application Development** - Full-stack development with Next.js, React, TypeScript
- 🔧 **Edge Computing Solutions** - Cloudflare Workers, Pages, D1, KV, Durable Objects
- 🛡️ **Security Tool Development** - Burp extensions, penetration testing tools, automation frameworks
- 🤖 **AI Integration** - LLM-powered applications, intelligent automation, custom AI solutions
- 🔍 **OSINT & Threat Intelligence** - Custom reconnaissance tools, threat feed aggregation, IOC correlation

**Get in Touch**: [teycirbensoltane.tn](https://teycirbensoltane.tn) | Available for freelance projects and consulting

---

## 📄 License

MIT License
