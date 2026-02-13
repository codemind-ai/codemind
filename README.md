# CodeMind — AI Security Guardian

<p align="center">
<pre align="center">
   ___          _      __  __ _           _ 
  / __\___   __| | ___|  \/  (_)_ __   __| |
 / /  / _ \ / _` |/ _ \ |\/| | | '_ \ / _` |
/ /__| (_) | (_| |  __/ |  | | | | | | (_| |
\____/\___/ \__,_|\___|_|  |_|_|_| |_|\__,_|
</pre>
</p>

<p align="center">
  <strong>🛡️ Enterprise-Grade Security for AI-Generated Code</strong><br>
  <em>Think before ship.</em>
</p>

<p align="center">
  <a href="https://pypi.org/project/codemind-mcp/">📦 PyPI</a> •
  <a href="https://codemind-ai.github.io/codemind">📖 Documentation</a> •
  <a href="#installation">🚀 Quick Start</a> •
  <a href="#available-tools">🔧 Tools</a>
</p>

<p align="center">
  <a href="https://pypi.org/project/codemind-mcp/">
    <img src="https://img.shields.io/pypi/v/codemind-mcp.svg" alt="PyPI Version">
  </a>
  <img src="https://img.shields.io/badge/python-3.10+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/MCP-Native-purple.svg" alt="MCP">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/privacy-100%25%20local-brightgreen.svg" alt="Privacy">
</p>

---

## Technical Overview

CodeMind transforms your AI coding assistant (Cursor, Windsurf, Claude Desktop) into a full security platform for the modern web. Specialized for **Next.js**, **React**, and **TypeScript**, it provides real-time oversight of AI-generated code across five security dimensions.


### Core Capabilities

| Module | Description |
|:---|:---|
| **Modular Skills** | Plugin-based agentic personas (Security, UI, Docs) with specialized prompts. |
| **Safety Lock** | Hard-coded protection against DROP, TRUNCATE, and unconditional DELETE. |
| **Intent Discovery**| Automatic detection of the optimal skill/persona for any given task. |
| **SAST Engine** | Detection of SQL injection, XSS, SSRF, and command injection patterns. |
| **Prompt Security** | Specialized detection for prompt injection and leak vulnerabilities. |
| **Secrets Detection**| Identification of hardcoded API keys and tokens with entropy analysis. |
| **IaC Scanning** | Security auditing for Dockerfiles, GitHub Actions, and docker-compose. |

---

## Quick Start

### Installation

```bash
# Global installation (recommended for CLI usage)
pip install codemind-mcp
```

### IDE Configuration (MCP)

Add the following to your MCP server configuration:

```json
{
  "mcpServers": {
"codemind": {
      "command": "codemind",
      "args": ["serve"]
    }
  }
}
```

### Usage

Simply include the trigger phrase in your chat prompt:
> "Generate a login endpoint for FastAPI. use codemind"

### Instant SaaS Protection

When you use the `use codemind` trigger, the Guardian automatically enforces essential protections for modern SaaS applications:

- **Rate Limiting**: Automatic protection against DDoS and brute-force attacks.
- **Data Isolation**: Enforcement of Row Level Security (RLS) to ensure users only access their own data.
- **Zod Validation**: Strict server-side schema validation to prevent untrusted client data from reaching your database.
- **Next.js & React Hardening**: Automated detection of unsafe `dangerouslySetInnerHTML`, exposed `NEXT_PUBLIC_` secrets, and insecure `localStorage` patterns.
- **CSRF Protection**: Auditing for missing security headers and insecure client-side data mutations.
- **Secure Default Props**: Enforcement of TypeScript best practices to eliminate "undefined" security gaps.
- **Prompt Security**: Hardened system prompts and injection-resistant templates for AI feature implementations.


---

## Available Tools

CodeMind exposes 15 MCP tools for seamless automated workflows:

*   `guard_code`: Static analysis for vulnerabilities (including Prompt Injection).
*   `detect_intent`: 🧠 Automatically identifies the best Skill for a given task.
*   `activate_skill`: Manually switch between agentic personas (Security, UI, Docs).
*   `run_workflow`: 🚀 Execute complex multi-step actions (e.g., `/deploy`, `/audit-deep`).
*   `list_skills`: View all available modular personas and their capabilities.
*   `audit_prompt`: Specialized analyzer for AI prompt security and leaks.
*   `scan_secrets`: Entropy-based credential detection.
*   `scan_dependencies`: Software Composition Analysis (SCA).
*   `scan_iac_file`: Infrastructure-as-Code auditing.
*   `deep_security_scan`: Consolidated multi-layer analysis.


---

## Strategic Roadmap

The transition from a hackathon project to a foundational security primitive.

### Phase 1: Foundation (Vibeathon)
- [x] Initial MCP Server implementation.
- [x] Core SAST pattern matching (50+ rules).
- [x] Secrets detection and SCA integration.
- [x] Launch Readiness Checklist.
- [x] **Prompt Security**: Advanced injection & jailbreak detection.

### Phase 2: Intelligence (Post-Launch)
- [x] **Semantic Analysis**: AST-based auditing for Python (+ taint-aware prompt detection).
- [x] **AI Slop Detection**: Pattern matching to remove redundant AI commentary.
### Phase 3: Autonomy (Scale)
- [x] **Modular Skill System**: Plugin-based architecture for specialized agentic personas.
- [x] **Safety Lock**: Hard-coded constraints for destructive database operations.
- [x] **Intent Discovery**: Real-time semantic detection of user tasks.
- [ ] **Taint Tracking**: Dataflow analysis to track untrusted input from source to sink.
- [ ] **Agentic Remediation**: Autonomous fix-verify loops for complex vulnerabilities.
- [ ] **CI/CD Native**: Direct integration with GitHub Actions as a first-class citizen.

### Phase 4: Expansion (Y Combinator Funding)
- [ ] **Universal Integration**: Support for all major LLM providers and coding platforms.
- [ ] **Real-time Protection**: Runtime monitoring for AI-agent executed tasks.
- [ ] **Global Standard**: Becoming the default security layer for AI-driven software development.

---

## Privacy Policy

CodeMind is built on the principle of **Local-First Security**.
- Your source code never leaves your machine.
- All pattern matching and analysis are performed locally.
- SCA requests to OSV.dev contain only package names and versions.
- No telemetry or tracking scripts are included.

---

## License

Distributed under the MIT License. See `LICENSE` for more information.
