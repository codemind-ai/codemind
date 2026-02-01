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
| 🔒 **Privacy-First** | Code never leaves your machine |
| 🎯 **IDE Integration** | Auto-injects prompts into Cursor, Claude Code, Windsurf, VS Code |
| 📝 **AI Commit Messages** | Generate conventional commit messages with AI |
| 🔍 **Rules Engine** | Custom security & best practice rules |
| 🚀 **GitHub Actions** | CI/CD integration ready |
| 💬 **Interactive Mode** | TUI for reviewing AI feedback |
| 🔌 **MCP Server** | Model Context Protocol support |

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

### Security Check

```bash
codemind rules list                # Show available presets
codemind rules check -p security-strict  # Check for secrets/vulnerabilities
```

### CI/CD Setup

```bash
codemind ci init                   # Generate GitHub Actions workflow
```

## ⚙️ All Commands

```bash
codemind install      # Install git pre-push hook
codemind uninstall    # Remove hook
codemind run          # Run review manually
codemind run -i       # Interactive mode
codemind commit       # Generate AI commit message
codemind rules list   # List rule presets
codemind rules check  # Check code against rules
codemind ci init      # Generate CI workflow
codemind config       # Show/create configuration
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

Create `.codemind.yml` in your repo:

```yaml
enabled: ask  # ask, always, or never

ide:
  preferred: [cursor, claude-code, windsurf]
  auto_inject: true

review:
  max_comments: 5
  fail_on: [security]

rules:
  preset: security-strict
  custom:
    - name: no-console-log
      pattern: "console\\.log"
      severity: warning
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
