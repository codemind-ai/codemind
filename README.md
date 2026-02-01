# 🧠 CodeMind

<p align="center">
  <strong>Think before ship.</strong>
</p>

<p align="center">
  <a href="https://codemind-ai.github.io/codemind">📖 Documentation</a> •
  <a href="https://www.bridgemind.ai/vibeathon">🏆 Vibeathon Entry</a> •
  <a href="#installation">⚡ Quick Start</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/python-3.10+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/vibeathon-2025-purple.svg" alt="Vibeathon">
</p>

---

**CodeMind** is an open-source, local-first orchestrator for AI code review. It runs **before `git push`** and leverages **your IDE's AI** (Cursor, Claude Code, Windsurf, VS Code) to deliver structured, consistent code reviews.

> 🏆 **Built for [Vibeathon 2025](https://www.bridgemind.ai/vibeathon)** — The open-source AI tools competition by Bridgemind.

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔒 **Privacy-First** | Code never leaves your machine. Local LLM support via Ollama. |
| 🤖 **Standalone AI** | Use OpenAI, Claude, or local models. No IDE subscription required. |
| 📝 **PR Generator** | Instantly generate professional Pull Request descriptions. |
| 🩺 **Smart Doctor** | Automated health checks and zero-friction onboarding. |
| 🚀 **API Gateway** | Full REST API (`codemind gateway`) for custom automation. |
| 💬 **Vibecoding** | Performance-focused reviews with high-energy AI coaching. |
| 🔌 **MCP Server** | Model Context Protocol support for LLM context injection. |
| 🔔 **Team Sync** | Automated Slack and Discord review notifications. |

## 📦 Installation

```bash
# Install from source
pip install -e .

# Install the git hook
codemind install
```

## 🚀 Quick Start

### Pre-push Review (Automatic)

```bash
git push
# CodeMind intercepts and runs AI review
```

### Generate Commit Message

```bash
git add .
codemind commit                    # Conventional commits
codemind commit -s simple          # Simple style
codemind commit --apply            # Auto-commit with AI message
```

### Interactive Review

```bash
codemind run -i                    # Review AI feedback in TUI
```

### Pull Request Description
```bash
codemind pr create                 # Generate professional PR summary
```

### Standalone Review (Ollama/OpenAI)
```bash
codemind run --vibe                # High-energy "Vibecoding" mode
```

### Network & Integrations
```bash
codemind gateway start             # Launch REST API server
codemind notify slack <webhook>    # Push results to Slack
```

### System Health
```bash
codemind doctor                    # Diagnostic checkup
codemind init --wizard             # 30-second interactive setup
```

### CI/CD Setup

```bash
codemind ci init                   # Generate GitHub Actions workflow
```

## ⚙️ All Commands

```bash
codemind install      # Install git pre-push hook
codemind uninstall    # Remove hook
codemind run          # Run review manually (--vibe for vibe mode)
codemind commit       # Generate AI commit message
codemind pr create    # Generate AI PR description
codemind doctor       # Run system health diagnostics
codemind gateway      # Start CodeMind REST API server
codemind notify       # Slack/Discord notification sync
codemind rules        # Manage and check review rules
codemind ci           # CI/CD (GitHub Actions) setup
codemind config       # Config management (--wizard for setup)
codemind serve        # Run as MCP server
codemind history      # View review history
```

## 🎯 Philosophy

| Principle | ✓ |
|-----------|---|
| No code generation by AI | ✅ |
| No AI API dependency | ✅ |
| User-owned AI | ✅ |
| Local-first, privacy-first | ✅ |
| Lightweight & fast | ✅ |

## 🤖 Supported IDEs

| IDE | Detection | Auto-Inject |
|-----|-----------|-------------|
| Cursor | ✅ | ✅ |
| Claude Code | ✅ | ✅ |
| Windsurf | ✅ | ✅ |
| VS Code (Copilot) | ✅ | ✅ |

## ⚙️ Configuration

Create `.codemind.yml` (or `.codemind.json`) in your repo:

```yaml
# When to run review: ask, always, or never
enabled: ask

# Standard AI Provider (ide, openai, or ollama)
llm:
  provider: ide
  model: gpt-4

# Custom review behavior
review:
  max_comments: 5
  vibe: true              # High-energy feedback

# Team Integrations
notifications:
  slack: https://hooks.slack.com/services/...
```

## 🔒 Rule Presets

| Preset | Rules | Focus |
|--------|-------|-------|
| `security-strict` | 7 | Hardcoded secrets, SQL injection, eval |
| `python` | 5 | Print statements, bare except, TODOs |
| `javascript` | 5 | console.log, any type, var usage |
| `minimal` | 1 | Essential secrets check |

## 🔌 MCP Server Mode

```bash
pip install codemind[mcp]
codemind serve
```

**Tools:** `review_diff`, `validate_ai_response`, `get_review_history`, `get_git_context`

## 🔐 Privacy & Security

- ✅ Code **never leaves your machine**
- ✅ No API keys required
- ✅ No telemetry or analytics
- ✅ Works with private repos
- ✅ Fully offline capable

## 🎯 Target Audience

- Indie builders & solo founders
- Privacy-focused developers
- Small teams without formal code review
- "Vibe coders" who need structure

## 🏆 Vibeathon

This project is an entry to [Vibeathon 2025](https://www.bridgemind.ai/vibeathon) by Bridgemind — a competition to build open-source tools that solve real problems for AI-assisted developers.

**Evaluation Criteria:**
- Usefulness (40%)
- Impact (25%)
- Execution (20%)
- Innovation (15%)

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

## 🔗 Links

- 📖 [Documentation](https://codemind-ai.github.io/codemind)
- 🐙 [GitHub](https://github.com/codemind-ai/codemind)
- 🏆 [Vibeathon](https://www.bridgemind.ai/vibeathon)

---

<p align="center">
  <strong>CodeMind</strong> — <em>Think before ship.</em>
</p>
