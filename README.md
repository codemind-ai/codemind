# 🧠 CodeMind

**Bring structure to AI code reviews — before you push.**

CodeMind is an open-source, local, and lightweight orchestrator for AI code review. It runs **before `git push`** and does **not use its own AI model or API** to generate code.

Instead, it:
- Uses **your IDE's AI** (Cursor, Claude Code, Windsurf, etc.)
- Delivers a **precise, structured review prompt**
- **Auto-injects** the prompt into your IDE chat
- Enforces a **consistent review process**
- **Validates** AI output quality

## 🎯 Philosophy

| Principle | ✓ |
|-----------|---|
| No code generation by AI | ✅ |
| No AI API dependency | ✅ |
| No GitHub lock-in | ✅ |
| User-owned AI | ✅ |
| Local-first, privacy-first | ✅ |
| Review only diffs | ✅ |
| Lightweight & fast | ✅ |

## 📦 Installation

```bash
# Install from source
pip install -e .

# Install the git hook
codemind install
```

## 🚀 Usage

### Automatic (via git hook)

Once installed, CodeMind runs automatically before each `git push`:

```
$ git push

🧠 CodeMind — Pre-push code review orchestrator

╭─────────────── 📊 Changes Detected ───────────────╮
│ Files changed   4                                  │
│ Lines           +212 / -87                         │
│ Files           main.py, utils.py, config.py...   │
╰────────────────────────────────────────────────────╯

Run AI review before push?
  [y] Yes   [n] No   [a] Always   [s] Skip once
Choice [y]:
```

The prompt is **automatically injected** into your IDE's AI chat!

### Manual

```bash
# Run review manually
codemind run

# Run without auto-inject (clipboard only)
codemind run --no-inject

# Specify base branch
codemind run --base origin/develop
```

### Other Commands

```bash
codemind install      # Install git hook
codemind uninstall    # Remove git hook
codemind config       # Show configuration
codemind config --init # Create config file
codemind status       # Check status
```

## ⚙️ Configuration

Create `.codemind.yml` in your repo:

```yaml
enabled: ask  # ask, always, or never

ide:
  preferred:
    - cursor
    - claude-code
    - windsurf
  auto_inject: true
  auto_submit: false

review:
  max_comments: 5
  strict_format: true
  fail_on:
    - security

rules:
  review_only_diff: true
  allow_feature_suggestions: false
```

## 🤖 Supported IDEs

| IDE | Detection | Auto-Inject | Chat Shortcut |
|-----|-----------|-------------|---------------|
| Cursor | ✅ | ✅ | Ctrl+L |
| Claude Code | ✅ | ✅ | Ctrl+Shift+P |
| Windsurf | ✅ | ✅ | Ctrl+L |
| VS Code (Copilot) | ✅ | ✅ | Ctrl+Shift+I |

## 📋 How It Works

1. **Hook triggers** on `git push`
2. **Extracts diff** between your branch and upstream
3. **Builds enhanced prompt** with strict rules
4. **Detects your IDE** window
5. **Auto-injects** prompt into AI chat
6. **You review** the AI's feedback
7. **Decide**: push or fix issues

## 🔌 MCP Server Mode

CodeMind can also run as an MCP (Model Context Protocol) server:

```bash
# Install MCP dependencies
pip install codemind[mcp]

# Run server (for AI client integration)
codemind serve

# Or with HTTP transport
codemind serve --transport streamable-http
```

**Available Tools:**
- `review_diff` - Generate AI review prompt for current changes
- `validate_ai_response` - Validate AI review output format
- `get_review_history` - Get past review entries
- `get_git_context` - Get git repository information

## 🔐 Privacy & Security

- ✅ Code **never leaves your machine** (processed by your local IDE AI)
- ✅ No API keys required
- ✅ No telemetry or analytics
- ✅ Works with private repos
- ✅ Fully offline capable

## 🎯 Target Audience

- Indie builders
- Solo founders
- Privacy-focused developers
- Small teams without formal code review

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

---

**CodeMind** — *The standard way developers run AI code review, before code ever leaves their machine.*
