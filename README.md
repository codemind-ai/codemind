# 🛡️ CodeMind MCP - AI Security & Quality Guardian

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
  <strong>🛡️ AI Security & Quality Guardian</strong><br>
  <em>Think before ship.</em>
</p>

<p align="center">
  <a href="https://codemind-ai.github.io/codemind">📖 Documentation</a> •
  <a href="#installation">🚀 Quick Start</a> •
  <a href="#available-tools">🔧 Tools</a>
</p>

<p align="center">
  <img src="https://img.shields.io/pypi/v/codemind?color=blue&label=PyPI" alt="PyPI">
  <img src="https://img.shields.io/badge/python-3.10+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/MCP-Supported-purple.svg" alt="MCP">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
</p>

---

## ❌ Without CodeMind

AI coding assistants generate code fast, but without oversight. You get:

- ❌ **Security vulnerabilities** slipping through unnoticed
- ❌ **"AI slop"** — bloated, repetitive, low-quality code
- ❌ **No code review** before pushing to production
- ❌ **Hallucinated patterns** that don't follow best practices

## ✅ With CodeMind

CodeMind MCP acts as your resident security and quality auditor. It reviews AI-generated code in real-time, catching issues before they reach your codebase.

Add `use codemind` to your prompt:

```
Create a user authentication system with password hashing
and session management. use codemind
```

---

## 💬 Example Input / Output

### User Prompt:
```
Create a login endpoint with email/password using FastAPI 
and PostgreSQL. use codemind
```

### AI Response with CodeMind:

```python
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from sqlalchemy import text
import os

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ✅ Credentials from environment, not hardcoded
DATABASE_URL = os.environ.get("DATABASE_URL")
JWT_SECRET = os.environ.get("JWT_SECRET")

class LoginRequest(BaseModel):
    email: EmailStr  # ✅ Validated email format
    password: str

@app.post("/login")
async def login(request: LoginRequest, db = Depends(get_db)):
    # ✅ Parameterized query - no SQL injection
    query = text("SELECT * FROM users WHERE email = :email")
    user = await db.execute(query, {"email": request.email})
    
    if not user or not pwd_context.verify(request.password, user.hashed_password):
        # ✅ Generic error - doesn't reveal if email exists
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return {"access_token": create_jwt_token(user.id)}
```

```
🛡️ Security Applied:
- Passwords hashed with bcrypt
- SQL uses parameterized queries (no injection)
- Credentials loaded from environment variables
- Generic error messages (no user enumeration)

📋 Required environment variables:
- DATABASE_URL: PostgreSQL connection string
- JWT_SECRET: Secret key for JWT token signing
```

---

## 🚀 Installation

### Install via pip

```bash
pip install codemind[mcp]
```

### Install in Cursor

Add to `.cursor/mcp.json`:

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

### Install in Claude Desktop

Add to your `claude_desktop_config.json`:

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

### Install in VS Code (Copilot)

Add to your MCP settings:

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

### Install in Windsurf

Add to your Windsurf MCP configuration:

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

---

## 🤖 AI Agent System Prompt

Add this system prompt to your AI agent to activate CodeMind automatically:

```markdown
## CodeMind Security Guardian

When writing or modifying code, ALWAYS follow this workflow:

1. **Fetch Documentation**: Before coding, use `query_docs()` to get current API docs
2. **Security First**: Never hardcode secrets, use parameterized queries, validate all input
3. **Scan Before Delivery**: Run `scan_and_fix(code)` before presenting code to user
4. **Include Context**: Add security notes and required env vars to your response

CRITICAL RULES:
- ❌ NEVER: password = "secret123" → ✅ ALWAYS: os.environ.get("PASSWORD")
- ❌ NEVER: f"SELECT * FROM users WHERE id = {id}" → ✅ ALWAYS: Parameterized queries
- ❌ NEVER: eval(user_input) → ✅ ALWAYS: Safe alternatives
- ❌ NEVER: Return code with security score < 80

When user says "use codemind", activate this full workflow automatically.
```

---

## 💡 Important Tips

### Add a Rule

To avoid typing `use codemind` in every prompt, add a rule to your MCP client:

- **Cursor**: Cursor Settings → Rules
- **Claude Code**: Add to `CLAUDE.md`
- **Or equivalent in your MCP client**

Example rule:

```
Always use CodeMind MCP to audit code for security vulnerabilities 
and clean code violations before generating or modifying code.
```

### Guardian Mode

Once connected, simply type in your chat:

> **You:** "use codemind"
>
> **AI:** "🛡️ Guardian Mode Activated! I've audited your code. Here are the security and quality findings..."

---

## 🔧 Available Tools

CodeMind MCP provides the following tools that LLMs can use:

| Tool | Description |
|------|-------------|
| 🛡️ `codemind` | Activate Guardian Mode — full security and quality audit for the current session. |
| 🔍 `guard_code` | Audit any code snippet for vulnerabilities, "AI slop", and anti-patterns. |
| ✨ `improve_code` | Automatically fix security issues and refactor for cleanliness. |
| 📊 `review_diff` | Generate a structured AI review prompt for your current git diff. |
| 📖 `best-practices` | **Resource**: Direct access to security and clean code patterns. |

---

## 🛠️ CLI & Git Integration

While the MCP server is the heart of CodeMind, we provide a CLI for local automation and git hooks.

### Install Git Hook

```bash
codemind install
```

### Git Workflow

CodeMind intercepts your `git push`, runs an AI review, and catches issues before they reach your team.

```bash
git push
# → CodeMind triggers and injects review into your IDE
```

### CLI Commands

| Command | Action |
|---------|--------|
| `codemind serve` | Start the MCP server |
| `codemind commit` | Generate AI commit messages (Conventional Commits) |
| `codemind pr create` | Generate AI PR descriptions |
| `codemind fix` | Apply suggested fixes locally |
| `codemind doctor` | Health check and setup wizard |

---

## 🔒 Privacy & Philosophy

- ✅ **100% Local**: Your code never leaves your machine.
- ✅ **Privacy-First**: No telemetry, no cloud, no API keys required.
- ✅ **Universal**: Works with Cursor, Claude Code, Windsurf, VS Code, and more.
- ✅ **User-Owned AI**: Leverages the AI assistant you're already using.

---

## 🎯 Who Is This For?

- **AI-Native Developers** — Who want a second set of eyes on AI-generated code.
- **Privacy-Focused Teams** — Who need code quality without cloud dependencies.
- **"Vibe Coders"** — Who need structure and security without slowing down.

---

## 📖 More Documentation

- [Full Documentation](https://codemind-ai.github.io/codemind) — Comprehensive guides and API reference
- [Configuration Guide](https://codemind-ai.github.io/codemind/configuration) — Customize CodeMind for your workflow
- [Troubleshooting](https://codemind-ai.github.io/codemind/troubleshooting) — Common issues and solutions

---

## 🤝 Connect With Us

- 🌐 [Website](https://codemind-ai.github.io/codemind)
- 💻 [GitHub](https://github.com/codemind-ai/codemind)
- 🐛 [Issues](https://github.com/codemind-ai/codemind/issues)

---

## ⭐ Star History

If you find CodeMind useful, please consider giving us a star! ⭐

---

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>CodeMind</strong> — <em>Think before ship.</em>
</p>
