# 🧠 CodeMind

<p align="center">
  <strong>The MCP Security & Quality Guardian.</strong><br>
  <em>Think before ship.</em>
</p>

<p align="center">
  <a href="https://codemind-ai.github.io/codemind">📖 Documentation</a> •
  <a href="https://github.com/upstash/context7">⚡ Inspiration</a> •
  <a href="#installation">🚀 Quick Start</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/python-3.10+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/MCP-Supported-purple.svg" alt="MCP">
</p>

---

**CodeMind** is an open-source **Model Context Protocol (MCP)** server that acts as a resident security and quality auditor for AI-powered development. It bridges your IDE's AI (Cursor, Claude Code, Windsurf, VS Code) with local security rules and clean code standards.

## 🛡️ Guardian Mode: "use codemind"

The primary way to use CodeMind is through its **Guardian Mode**. Once connected to your AI assistant via MCP, you can simply trigger it in your chat:

> **You:** "use codemind"
>
> **AI:** "🛡️ Guardian Mode Activated! I've audited your code. Here are the security and quality findings..."

## ✨ MCP Features

| Tool | Description |
|------|-------------|
| 🔍 `guard_code` | Audit any code snippet for vulnerabilities and "AI slop". |
| ✨ `improve_code` | Automatically fix security issues and refactor for cleanliness. |
| 📊 `review_diff` | Generate a structured AI review prompt for your current git diff. |
| 🛡️ `codemind` | Activate the full Guardian suite for current session. |
| 📖 `best-practices` | Resource: Direct access to security and clean code patterns. |

## 🚀 Quick Start (MCP)

### 1. Install CodeMind
```bash
pip install "codemind[mcp]"
```

### 2. Add to Claude Desktop
Add this to your `claude_desktop_config.json`:
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

### 3. Use in your IDE
Just ask your AI: **"Can you audit my code using codemind?"** or **"use codemind"**.

---

## 🛠️ CLI & Git Integration (Secondary)

While the MCP server is the heart of CodeMind, we provide a CLI for local automation and git hooks.

### Installation
```bash
# Install git pre-push hook
codemind install
```

### Git Workflow
CodeMind intercepts your `git push`, runs an AI review using your IDE's local AI, and catches issues before they reach your team.

```bash
git push
# CodeMind triggers and injects review into your IDE
```

### CLI Commands
| Command | Action |
|---------|--------|
| `codemind commit` | Generate AI commit messages (Conventional) |
| `codemind pr create` | Generate AI PR descriptions |
| `codemind fix` | Apply suggested fixes locally |
| `codemind doctor` | Health check and wizard setup |

---

## 🔒 Privacy & Philosophy

- ✅ **100% Local**: Code never leaves your machine.
- ✅ **Privacy-First**: No telemetry, no cloud, no API keys required.
- ✅ **Universal**: Works with Cursor, Claude Code, Windsurf, and VS Code.
- ✅ **User-Owned AI**: Leverages the AI you're already using.

## 🎯 Target Audience

- **AI-Native Developers**: Who want a second set of eyes on AI-generated code.
- **Privacy-focused Teams**: Who need code quality without cloud dependencies.
- **"Vibe Coders"**: Who need structure and security without slowing down.

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>CodeMind</strong> — <em>Think before ship.</em>
</p>
