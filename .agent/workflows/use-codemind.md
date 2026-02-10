---
description: Use CodeMind MCP for security scanning and clean code generation
---

# CodeMind Security Guardian Skill

This skill activates CodeMind MCP for security-first code generation. Use this when writing any code that involves authentication, databases, file handling, or user input.

## When to Use

Activate this skill when user requests involve:
- Login/registration/authentication
- Database queries (SQL, NoSQL)
- File uploads/downloads
- API endpoints
- Form handling
- Payment processing
- Any user input handling

## Workflow

### Step 1: Analyze the Request

Identify:
- What frameworks/libraries are needed? (React, FastAPI, Django, etc.)
- What security-sensitive features? (auth, database, file upload)
- What language? (Python, JavaScript, TypeScript)

### Step 2: Fetch Documentation
// turbo

For each detected framework, fetch current docs:

```
Use query_docs tool with relevant library:
- FastAPI: query_docs("/tiangolo/fastapi", "authentication security")
- React: query_docs("/facebook/react", "forms input validation")
- Prisma: query_docs("/prisma/prisma", "parameterized queries")
- SQLAlchemy: query_docs("/sqlalchemy/sqlalchemy", "safe queries")
```

### Step 3: Write Secure Code

Follow these STRICT rules:

**🔴 CRITICAL SECURITY:**
```
❌ NEVER: password = "secret123"  
✅ ALWAYS: password = os.environ.get("PASSWORD")

❌ NEVER: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
✅ ALWAYS: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

❌ NEVER: element.innerHTML = userInput
✅ ALWAYS: element.textContent = userInput

❌ NEVER: os.system(user_command)
✅ ALWAYS: subprocess.run([cmd, arg], shell=False)

❌ NEVER: eval(user_input)
✅ ALWAYS: Use safe alternatives (JSON.parse, ast.literal_eval)
```

**🟡 CLEAN CODE:**
- Use descriptive variable names (not `data`, `result`, `temp`)
- No redundant comments
- No console.log/print statements
- Specific error handling (not bare except)

### Step 4: Scan and Fix
// turbo

Before presenting code, run security scan:

```
Use scan_and_fix tool with:
- code: The generated code
- language: "python" or "javascript" or "typescript"
- filename: "app.py" or "component.tsx"
```

If issues are found, use the fixed code from the result.

### Step 5: Launch readiness check
// turbo

If the code is part of a production feature (auth, forms, API), run the launch audit:

```
Use audit_launch_checklist tool with:
- code: The final code
- filename: "app.py" or "schema.sql"
```

If items fail, use `get_secure_boilerplate` to fetch missing security layers.

### Step 6: Format Response

Include in your response:

1. **Code** with security best practices applied

2. **Security note:**
```
🛡️ Security: Passwords hashed with bcrypt, SQL uses parameterized queries
```

3. **Required environment variables:**
```
📋 Required environment variables:
- DATABASE_URL: Your database connection string
- JWT_SECRET: Random secret for JWT tokens
```

## Example Usage

**User:** "Create a login system with FastAPI and PostgreSQL, use codemind"

**You:**
1. Call `query_docs("/tiangolo/fastapi", "authentication JWT security")`
2. Call `query_docs("/sqlalchemy/sqlalchemy", "parameterized queries")`
3. Write secure code following the rules above
4. Call `scan_and_fix(code=your_code, language="python")`
5. Return secure code with security notes

## Available Tools

| Tool | Purpose |
|------|---------|
| `resolve_library(name)` | Find library ID for docs |
| `query_docs(library_id, query)` | Fetch current documentation |
| `guard_code(code, language)` | Security & quality audit |
| `scan_and_fix(code, language)` | Detect and auto-fix vulnerabilities |
| `improve_code(code)` | Refactor and improve code |
| `audit_launch_checklist(code)` | Essential production readiness scan |
| `get_secure_boilerplate(framework, feature)` | Fetch secure production examples |

## Quick Trigger

When user adds any of these to their prompt:
- "use codemind"
- "secure code"
- "production ready"
- "ready to launch"
- "ship it"

Automatically activate this full workflow.

---

**Remember: You are the security gate. No vulnerable code passes through.**
