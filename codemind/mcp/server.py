"""CodeMind MCP Server.

Exposes CodeMind functionality as an MCP server with tools for:
- Up-to-date documentation fetching (like Context7)
- Security and quality auditing (Guardian)
- Reviewing git diffs with AI prompts
- Auto-fixing code issues
"""

from pathlib import Path
from typing import Optional, List

from mcp.server.fastmcp import FastMCP

from ..git.diff import get_diff, DiffResult
from ..git.context import get_context, GitContext
from ..prompt.builder import build_prompt, PromptConfig, BuiltPrompt
from ..validate.parser import parse_review, ParsedReview
from ..validate.rules import validate_review, ValidationConfig, ValidationResult
from ..history import (
    save_review,
    get_recent_reviews,
    get_review_stats,
    clear_history,
    ReviewEntry
)
from .guard import Guardian, GuardType, GuardReport, GuardIssue
from .docs import (
    get_fetcher,
    detect_frameworks,
    LibraryInfo,
    DocumentationResult,
    LIBRARY_ALIASES,
    HAS_HTTPX
)
from ..llm.fixer import CodeFixer
from ..llm import get_llm_provider
from ..cli.config import load_config


# Initialize MCP Server
mcp = FastMCP("CodeMind")


@mcp.tool()
def review_diff(
    base: Optional[str] = None,
    max_comments: int = 5,
    strict_format: bool = True,
    extra_rules: Optional[list[str]] = None
) -> dict:
    """
    Generate an AI code review prompt for git diff changes.
    
    This tool extracts the diff between your current branch and a base branch,
    then generates a structured prompt for AI code review.
    
    Args:
        base: Base ref to diff against (default: auto-detect upstream)
        max_comments: Maximum number of comments in review (default: 5)
        strict_format: Require strict output format (default: True)
        extra_rules: Additional rules to include in the prompt
    
    Returns:
        Dict containing the prompt content, token estimate, and file info
    """
    try:
        # Get git context
        context = get_context()
        
        # Get diff
        diff_result = get_diff(base=base, exclude_binary=True)
        
        if diff_result.is_empty:
            return {
                "success": False,
                "error": "No changes detected between branches",
                "files_changed": 0
            }
        
        # Build prompt
        config = PromptConfig(
            max_comments=max_comments,
            strict_format=strict_format,
            extra_rules=extra_rules or []
        )
        built = build_prompt(diff_result, context, config)
        
        # Save to history
        save_review(
            branch=context.current_branch,
            files_changed=built.file_count,
            lines_added=diff_result.total_additions,
            lines_deleted=diff_result.total_deletions,
            token_estimate=built.token_estimate,
            prompt_content=built.content,
            files=[f.path for f in diff_result.files]
        )
        
        return {
            "success": True,
            "prompt": built.content,
            "token_estimate": built.token_estimate,
            "files_changed": built.file_count,
            "lines_added": diff_result.total_additions,
            "lines_deleted": diff_result.total_deletions,
            "branch": context.current_branch,
            "truncated": built.truncated,
            "warning": built.warning
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def validate_ai_response(
    response: str,
    max_comments: int = 5,
    fail_on_critical: bool = True,
    fail_on_warning: bool = False
) -> dict:
    """
    Validate an AI code review response for proper format and issues.
    
    This tool parses the AI's response and validates it against configured rules.
    Use this after receiving an AI code review to check for critical issues.
    
    Args:
        response: The AI's code review response text
        max_comments: Maximum expected comments (default: 5)
        fail_on_critical: Fail validation if critical issues found (default: True)
        fail_on_warning: Fail validation if warnings found (default: False)
    
    Returns:
        Dict containing parsed issues and validation result
    """
    try:
        # Parse the response
        parsed = parse_review(response)
        
        # Validate
        config = ValidationConfig(
            max_comments=max_comments,
            fail_on_critical=fail_on_critical,
            fail_on_warning=fail_on_warning
        )
        result = validate_review(parsed, config)
        
        # Format issues for output
        issues_list = [
            {
                "severity": issue.severity.value,
                "message": issue.message,
                "file": issue.file_path,
                "line": issue.line_number
            }
            for issue in parsed.issues
        ]
        
        return {
            "success": True,
            "is_valid": result.is_valid,
            "is_clean": parsed.is_clean,
            "is_valid_format": parsed.is_valid_format,
            "critical_count": parsed.critical_count,
            "warning_count": parsed.warning_count,
            "suggestion_count": parsed.suggestion_count,
            "total_issues": parsed.total_issues,
            "issues": issues_list,
            "errors": result.errors,
            "warnings": result.warnings
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def get_review_history(count: int = 10) -> dict:
    """
    Get recent code review history.
    
    Returns the most recent code review entries including branch names,
    file counts, and timestamps.
    
    Args:
        count: Number of recent reviews to return (default: 10)
    
    Returns:
        Dict containing list of recent reviews and statistics
    """
    try:
        recent = get_recent_reviews(count)
        stats = get_review_stats()
        
        reviews_list = [
            {
                "timestamp": entry.timestamp,
                "branch": entry.branch,
                "files_changed": entry.files_changed,
                "lines_added": entry.lines_added,
                "lines_deleted": entry.lines_deleted,
                "token_estimate": entry.token_estimate,
                "files": entry.files
            }
            for entry in recent
        ]
        
        return {
            "success": True,
            "reviews": reviews_list,
            "statistics": stats
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def get_git_context() -> dict:
    """
    Get current git repository context.
    
    Returns information about the current branch, upstream,
    and repository state.
    
    Returns:
        Dict containing git context information
    """
    try:
        ctx = get_context()
        
        return {
            "success": True,
            "repo_root": str(ctx.repo_root),
            "current_branch": ctx.current_branch,
            "upstream_branch": ctx.upstream_branch,
            "remote_name": ctx.remote_name,
            "is_dirty": ctx.is_dirty,
            "has_staged": ctx.has_staged,
            "commit_count": ctx.commit_count
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@mcp.resource("history://stats")
def history_stats() -> str:
    """Get review history statistics as a resource."""
    stats = get_review_stats()
    
    if stats["total_reviews"] == 0:
        return "No reviews in history yet."
    
    return f"""CodeMind Review Statistics
==========================
Total Reviews: {stats['total_reviews']}
Total Files Reviewed: {stats['total_files_reviewed']}
Total Lines Changed: {stats['total_lines_changed']}
Avg Files per Review: {stats['avg_files_per_review']:.1f}
First Review: {stats['first_review']}
Last Review: {stats['last_review']}
"""


# =============================================================================
# DOCUMENTATION TOOLS (Like Context7)
# =============================================================================

@mcp.tool()
def resolve_library(name: str) -> dict:
    """
    Resolve a library or framework name to a documentation ID.
    
    Use this to find the correct library ID before calling query_docs.
    Works like Context7's resolve-library-id.
    
    Examples:
        resolve_library("react") → "/facebook/react"
        resolve_library("next.js") → "/vercel/next.js"
        resolve_library("fastapi") → "/tiangolo/fastapi"
    
    Args:
        name: Library or framework name (e.g., "react", "django", "express")
    
    Returns:
        Dict with library_id, name, and description
    """
    if not HAS_HTTPX:
        return {
            "success": False,
            "error": "Documentation fetching requires httpx. Install with: pip install httpx"
        }
    
    try:
        fetcher = get_fetcher()
        if not fetcher:
            return {
                "success": False,
                "error": "Could not initialize documentation fetcher"
            }
        
        result = fetcher.resolve_library(name)
        
        if result:
            return {
                "success": True,
                "library_id": result.library_id,
                "name": result.name,
                "description": result.description,
                "snippet_count": result.snippet_count,
                "hint": f"Use query_docs(\"{result.library_id}\", \"your question\") to fetch documentation"
            }
        else:
            # Return available aliases as suggestions
            suggestions = [k for k in LIBRARY_ALIASES.keys() if name.lower() in k][:5]
            return {
                "success": False,
                "error": f"Could not resolve library '{name}'",
                "suggestions": suggestions if suggestions else list(LIBRARY_ALIASES.keys())[:10]
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def query_docs(library_id: str, query: str, max_tokens: int = 5000) -> dict:
    """
    Fetch up-to-date documentation for a library.
    
    Use this to get current, version-specific documentation and code examples.
    Works like Context7's query-docs.
    
    IMPORTANT: Call resolve_library first to get the correct library_id,
    unless you already know it (e.g., "/facebook/react", "/vercel/next.js").
    
    Examples:
        query_docs("/facebook/react", "useState hook examples")
        query_docs("/vercel/next.js", "app router middleware")
        query_docs("/tiangolo/fastapi", "dependency injection")
    
    Args:
        library_id: Context7-compatible library ID (e.g., "/facebook/react")
        query: The question or topic to get documentation for
        max_tokens: Maximum tokens in response (default: 5000)
    
    Returns:
        Dict with documentation content, source URL, and success status
    """
    if not HAS_HTTPX:
        return {
            "success": False,
            "error": "Documentation fetching requires httpx. Install with: pip install httpx"
        }
    
    try:
        fetcher = get_fetcher()
        if not fetcher:
            return {
                "success": False,
                "error": "Could not initialize documentation fetcher"
            }
        
        result = fetcher.query_docs(library_id, query, max_tokens)
        
        if result.success:
            return {
                "success": True,
                "library_id": result.library_id,
                "query": result.query,
                "documentation": result.content,
                "source_url": result.source_url,
                "hint": "Use this documentation to write current, verified code"
            }
        else:
            return {
                "success": False,
                "library_id": library_id,
                "query": query,
                "error": result.error
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def detect_code_libraries(code: str) -> dict:
    """
    Detect frameworks and libraries used in a code snippet.
    
    Analyzes imports and patterns to identify libraries, then suggests
    documentation queries for each.
    
    Args:
        code: Source code to analyze
    
    Returns:
        Dict with detected libraries and suggested documentation queries
    """
    detected = detect_frameworks(code)
    
    if not detected:
        return {
            "success": True,
            "detected": [],
            "message": "No specific frameworks detected. Code appears to use standard library only."
        }
    
    suggestions = []
    for lib in detected:
        lib_id = LIBRARY_ALIASES.get(lib.lower())
        suggestions.append({
            "library": lib,
            "library_id": lib_id,
            "suggested_action": f"query_docs(\"{lib_id}\", \"best practices and patterns\")" if lib_id else f"resolve_library(\"{lib}\")"
        })
    
    return {
        "success": True,
        "detected": detected,
        "suggestions": suggestions,
        "hint": "Fetch documentation for these libraries to ensure you're using current APIs"
    }


# =============================================================================
# GUARDIAN TOOLS (Security & Quality)
# =============================================================================


@mcp.tool()
def guard_code(code: str, language: str = "python", filename: str = "snippet.code") -> dict:
    """
    🛡️ Perform comprehensive security and quality audit on code.
    
    DETECTS:
    - SQL Injection vulnerabilities
    - XSS (Cross-Site Scripting)
    - Command Injection
    - Path Traversal
    - Credential Exposure
    - Unsafe Deserialization
    - SSRF (Server-Side Request Forgery)
    - AI Slop (redundant comments, poor naming)
    - And 50+ more security patterns
    
    Args:
        code: The code content to audit
        language: Programming language (python, javascript, typescript, etc.)
        filename: Optional filename for better context
    
    Returns:
        Comprehensive audit report with issues categorized by type and severity
    """
    guardian = Guardian()
    report = guardian.audit(code, filename)
    
    # Categorize issues
    security_issues = []
    quality_issues = []
    vulnerability_summary = {}
    
    for issue in report.issues:
        issue_dict = {
            "severity": issue.severity.value,
            "message": issue.message,
            "line": issue.line,
            "snippet": issue.code_snippet,
            "suggestion": issue.suggestion,
            "vulnerability_type": issue.vulnerability_type
        }
        
        if issue.type == GuardType.SECURITY:
            security_issues.append(issue_dict)
            vuln_type = issue.vulnerability_type or "OTHER"
            if vuln_type not in vulnerability_summary:
                vulnerability_summary[vuln_type] = 0
            vulnerability_summary[vuln_type] += 1
        else:
            quality_issues.append(issue_dict)
    
    # Generate severity counts
    critical_count = sum(1 for i in report.issues if i.severity.value == "critical")
    warning_count = sum(1 for i in report.issues if i.severity.value == "warning")
    info_count = sum(1 for i in report.issues if i.severity.value == "info")
    
    # Build visual score bar
    def make_score_bar(score: int, width: int = 20) -> str:
        """Generate a visual progress bar for scores."""
        filled = int((score / 100) * width)
        empty = width - filled
        
        if score >= 90:
            color = "🟢"
            bar_char = "█"
        elif score >= 70:
            color = "🟡"
            bar_char = "█"
        else:
            color = "🔴"
            bar_char = "█"
        
        bar = bar_char * filled + "░" * empty
        return f"{color} [{bar}] {score}/100"
    
    # Build formatted summary
    status_emoji = "✅" if report.is_safe else "🚨"
    quality_emoji = "✨" if report.is_clean else "⚠️"
    
    # Calculate separate scores
    security_score = 100 - (len([i for i in report.issues if i.type == GuardType.SECURITY]) * 10)
    security_score = max(0, security_score)
    quality_score = 100 - (len([i for i in report.issues if i.type != GuardType.SECURITY]) * 5)
    quality_score = max(0, quality_score)
    
    summary_lines = [
        f"## 🛡️ Guardian Audit Report",
        "",
        f"### Overall Score: {report.score}/100",
        f"```",
        f"{make_score_bar(report.score)}",
        f"```",
        "",
        f"### Security {status_emoji}",
        f"```",
        f"{make_score_bar(security_score)} {'PASSED' if report.is_safe else 'ISSUES FOUND'}",
        f"```",
        "",
        f"### Quality {quality_emoji}",
        f"```",
        f"{make_score_bar(quality_score)} {'Clean' if report.is_clean else 'Needs work'}",
        f"```",
        "",
        f"### Issues Found:",
        f"- 🔴 Critical: {critical_count}",
        f"- 🟡 Warning: {warning_count}",
        f"- 🔵 Info: {info_count}",
    ]
    
    if vulnerability_summary:
        summary_lines.append("")
        summary_lines.append("### Vulnerabilities by Type:")
        for vuln_type, count in sorted(vulnerability_summary.items()):
            summary_lines.append(f"- {vuln_type}: {count}")
    
    return {
        "success": True,
        "score": report.score,
        "is_safe": report.is_safe,
        "is_clean": report.is_clean,
        "security_issues": security_issues,
        "quality_issues": quality_issues,
        "vulnerability_summary": vulnerability_summary,
        "counts": {
            "critical": critical_count,
            "warning": warning_count,
            "info": info_count,
            "total": len(report.issues)
        },
        "summary": "\n".join(summary_lines)
    }


@mcp.tool()
def improve_code(code: str, issue_descriptions: Optional[str] = None, filename: str = "snippet.code") -> dict:
    """
    Automatically improve code by fixing security and quality issues.
    
    If no issue_descriptions are provided, it first runs an audit and fixes found issues.
    
    Args:
        code: Code to improve
        issue_descriptions: Optional text describing issues to fix
        filename: Optional filename for context
    
    Returns:
        Improved code and summary of changes
    """
    guardian = Guardian()
    
    # If no issues provided, find them
    if not issue_descriptions:
        report = guardian.audit(code, filename)
        if not report.issues:
            return {
                "success": True,
                "improved_code": code,
                "message": "No issues found to improve."
            }
        issue_descriptions = "\n".join([f"- {i.message} (line {i.line})" for i in report.issues])
    
    try:
        config = load_config()
        llm = get_llm_provider(
            provider_type=config.llm.provider,
            model=config.llm.model,
            api_key=config.llm.api_key,
            base_url=config.llm.base_url
        )
        fixer = CodeFixer(llm)
        
        improved_code = fixer.generate_fix(filename, code, issue_descriptions)
        
        # Verify the fix
        new_report = guardian.audit(improved_code, filename)
        
        return {
            "success": True,
            "improved_code": improved_code,
            "initial_issues": issue_descriptions,
            "new_score": new_report.score,
            "is_fixed": new_report.score > 90,
            "remaining_issues": len(new_report.issues)
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def scan_and_fix(code: str, language: str = "python", filename: str = "code.py") -> dict:
    """
    🔒 SECURITY SCANNER: Detect and auto-fix vulnerabilities in one action.
    
    Scans for dangerous patterns and immediately provides fixed code:
    - SQL Injection → Parameterized queries
    - XSS → Proper escaping/sanitization
    - Command Injection → Safe subprocess calls
    - Credential Exposure → Environment variables
    - Path Traversal → Safe path handling
    - And more...
    
    Args:
        code: Source code to scan and fix
        language: Programming language (python, javascript, typescript)
        filename: Filename for context
    
    Returns:
        Original issues found, fixed code, and diff showing changes
    """
    import difflib
    
    guardian = Guardian()
    report = guardian.audit(code, filename)
    
    if not report.issues:
        return {
            "success": True,
            "has_issues": False,
            "score": 100,
            "message": "✅ No security issues detected! Code is clean.",
            "fixed_code": code
        }
    
    # Categorize by vulnerability type
    vuln_summary = {}
    critical_issues = []
    all_suggestions = []
    
    for issue in report.issues:
        if issue.type == GuardType.SECURITY:
            vuln_type = issue.vulnerability_type or "OTHER"
            if vuln_type not in vuln_summary:
                vuln_summary[vuln_type] = []
            vuln_summary[vuln_type].append({
                "line": issue.line,
                "snippet": issue.code_snippet,
                "message": issue.message,
                "suggestion": issue.suggestion
            })
            
            if issue.severity.value == "critical":
                critical_issues.append(issue)
        
        if issue.suggestion:
            all_suggestions.append(f"Line {issue.line}: {issue.message}\n   → FIX: {issue.suggestion}")
    
    # Try to auto-fix using LLM
    fix_prompt = []
    fix_prompt.append("Fix the following security vulnerabilities in this code:\n")
    for issue in report.issues:
        if issue.suggestion:
            fix_prompt.append(f"- Line {issue.line}: {issue.message}")
            fix_prompt.append(f"  Fix: {issue.suggestion}")
    
    fixed_code = code
    diff_output = ""
    fix_applied = False
    
    try:
        config = load_config()
        llm = get_llm_provider(
            provider_type=config.llm.provider,
            model=config.llm.model,
            api_key=config.llm.api_key,
            base_url=config.llm.base_url
        )
        fixer = CodeFixer(llm)
        
        fixed_code = fixer.generate_fix(filename, code, "\n".join(fix_prompt))
        
        # Generate diff
        diff_lines = difflib.unified_diff(
            code.splitlines(keepends=True),
            fixed_code.splitlines(keepends=True),
            fromfile=f"original/{filename}",
            tofile=f"fixed/{filename}"
        )
        diff_output = "".join(diff_lines)
        fix_applied = True
        
        # Verify fix
        new_report = guardian.audit(fixed_code, filename)
        new_score = new_report.score
        
    except Exception as e:
        new_score = report.score
        diff_output = f"Auto-fix unavailable: {e}\n\nManual fixes required:\n" + "\n".join(all_suggestions)
    
    # Build report
    report_lines = [
        "# 🔒 Security Scan Report",
        "",
        f"**Original Score:** {report.score}/100",
    ]
    
    if fix_applied:
        report_lines.append(f"**Fixed Score:** {new_score}/100")
    
    report_lines.extend([
        "",
        "## 🚨 Vulnerabilities Found:",
        ""
    ])
    
    for vuln_type, issues in vuln_summary.items():
        report_lines.append(f"### {vuln_type} ({len(issues)} issue{'s' if len(issues) > 1 else ''})")
        for issue in issues[:3]:  # Show max 3 per type
            report_lines.append(f"- **Line {issue['line']}**: `{issue['snippet'][:60]}...`")
            if issue['suggestion']:
                report_lines.append(f"  - 💡 {issue['suggestion']}")
        if len(issues) > 3:
            report_lines.append(f"  - ...and {len(issues) - 3} more")
        report_lines.append("")
    
    return {
        "success": True,
        "has_issues": True,
        "original_score": report.score,
        "fixed_score": new_score if fix_applied else None,
        "fix_applied": fix_applied,
        "vulnerabilities": vuln_summary,
        "critical_count": len(critical_issues),
        "total_issues": len(report.issues),
        "fixed_code": fixed_code,
        "diff": diff_output,
        "report": "\n".join(report_lines),
        "suggestions": all_suggestions[:10]  # Top 10 suggestions
    }



@mcp.resource("guardian://best-practices")
def guardian_best_practices() -> str:
    """Get comprehensive security and clean code best practices."""
    return """# 🛡️ CodeMind Guardian - Best Practices

## Security Essentials

### Secrets & Credentials
- ❌ NEVER hardcode passwords, API keys, tokens, or secrets
- ✅ Use environment variables: `os.environ.get("API_KEY")`
- ✅ Use secret managers (AWS Secrets Manager, HashiCorp Vault)
- ✅ Add secrets to .gitignore and .env.example

### Input Validation
- ❌ NEVER trust user input directly
- ✅ Validate and sanitize ALL user input
- ✅ Use parameterized queries for databases:
  ```python
  # BAD: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
  # GOOD: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
  ```

### Dangerous Functions (AVOID)
- Python: `eval()`, `exec()`, `pickle.load()` with untrusted data
- JavaScript: `eval()`, `innerHTML`, `document.write()` with user input
- General: `yaml.load()` → use `yaml.safe_load()`
- General: `subprocess.shell=True` with user input

### Authentication & Authorization
- ✅ Hash passwords with bcrypt or argon2 (never MD5/SHA1)
- ✅ Use HTTPS everywhere
- ✅ Implement rate limiting
- ✅ Validate JWT tokens server-side

---

## Clean Code Principles

### Naming
- ❌ Avoid: `data`, `result`, `temp`, `val`, `x`, `handler`
- ✅ Use: `userProfile`, `validationErrors`, `cachedResponse`
- ✅ Functions should describe actions: `calculateTotalPrice()`, `validateUserInput()`

### Comments (No AI Slop)
- ❌ Avoid: "// This function adds two numbers"
- ❌ Avoid: "// Loop through the array"
- ✅ Explain WHY not WHAT: "// Rate limit to prevent DDoS attacks"

### SOLID Principles
1. **Single Responsibility**: One function = one job
2. **Open/Closed**: Extend, don't modify
3. **Liskov Substitution**: Subtypes must be substitutable
4. **Interface Segregation**: Small, focused interfaces
5. **Dependency Inversion**: Depend on abstractions

### DRY (Don't Repeat Yourself)
- Extract repeated code into functions
- Use constants for magic numbers/strings
- Create reusable utilities

---

## Framework-Specific Patterns

### React/Next.js
- Use `useCallback` and `useMemo` for expensive operations
- Avoid inline function definitions in JSX
- Use React Query/SWR for data fetching
- Validate props with TypeScript or PropTypes

### FastAPI/Python
- Use Pydantic models for request validation
- Implement dependency injection for testing
- Use async/await for I/O-bound operations
- Add proper exception handlers

### Express/Node.js
- Use helmet.js for security headers
- Validate with Joi or Zod
- Use async error handlers
- Implement proper logging

---

## Before Committing Checklist

- [ ] No hardcoded secrets
- [ ] All user input validated
- [ ] No debug/print statements
- [ ] No TODO comments left unresolved
- [ ] Functions are small and focused
- [ ] Variable names are descriptive
- [ ] guard_code score ≥ 90
"""


@mcp.prompt()
def code_review_prompt(
    focus_area: str = "general",
    max_comments: str = "5"
) -> str:
    """
    Generate a guided prompt for AI code review.
    
    Args:
        focus_area: Area to focus on (general, security, performance, refactor)
        max_comments: Maximum number of comments
    """
    focus_rules = {
        "general": "Review for bugs, code smells, and maintainability issues.",
        "security": "Focus especially on security vulnerabilities, injection attacks, and data exposure.",
        "performance": "Focus on performance bottlenecks, memory leaks, and optimization opportunities.",
        "refactor": "Suggest refactoring opportunities and design improvements."
    }
    
    focus_instruction = focus_rules.get(focus_area, focus_rules["general"])
    
    return f"""Please use the review_diff tool to get the current code changes, 
then provide a code review with the following focus:

{focus_instruction}

Limit your review to {max_comments} comments maximum.
Use the validate_ai_response tool to verify your response format.
"""


@mcp.prompt()
def secure_implementation_prompt(code: str) -> str:
    """
    Generate a prompt to implement code securely.
    
    Args:
        code: The initial code or requirements
    """
    return f"""You are implementing the following code:
{code}

To ensure high quality and security, please follow these steps:
1. Review the best practices in 'guardian://best-practices'.
2. Use the 'guard_code' tool to audit your implementation.
3. If issues are found, use the 'improve_code' tool or refactor until the score is > 90.
4. Ensure no 'AI slop' (redundant comments, generic names) is present.
"""


@mcp.prompt()
def codemind() -> str:
    """
    🛡️ USE CODEMIND - Unified security & quality workflow.
    
    Add "use codemind" at the end of ANY coding request to activate:
    - Automatic documentation fetching for used frameworks
    - Security vulnerability scanning (SQL injection, XSS, etc.)
    - Code quality audit (no AI slop)
    - Auto-fix for all detected issues
    
    Example: "Make me a login form with validation... use codemind"
    """
    return '''🛡️ **CODEMIND ACTIVATED** - Security & Quality Mode

When the user adds "use codemind" to their request, you MUST follow this workflow:

---

## 🔄 AUTOMATIC WORKFLOW

### STEP 1: Analyze Request
Identify what the user is building:
- What frameworks/libraries are needed? (React, FastAPI, Django, etc.)
- What security-sensitive features? (auth, database, file upload, payments)
- What language? (Python, JavaScript, TypeScript)

### STEP 2: Fetch Documentation (AUTOMATIC)
For each detected framework, automatically call:
```
resolve_library("framework_name")
query_docs(library_id, "relevant topic")
```

Common scenarios:
- Login/Register → fetch auth library docs (NextAuth, Passport, etc.)
- Database → fetch ORM docs (Prisma, SQLAlchemy, Sequelize)
- API → fetch framework docs (FastAPI, Express, etc.)
- Forms → fetch validation docs (Zod, Pydantic)

### STEP 3: Write Secure Code
Follow these STRICT rules:

**🔴 CRITICAL SECURITY (NEVER VIOLATE):**
```
❌ NEVER: password = "secret123"  
✅ ALWAYS: password = os.environ.get("PASSWORD")

❌ NEVER: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
✅ ALWAYS: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

❌ NEVER: element.innerHTML = userInput
✅ ALWAYS: element.textContent = userInput (or sanitize with DOMPurify)

❌ NEVER: os.system(user_command)
✅ ALWAYS: subprocess.run([cmd, arg], shell=False)

❌ NEVER: eval(user_input) or exec(user_input)
✅ ALWAYS: Use safe alternatives (JSON.parse, ast.literal_eval)
```

**🟡 CODE QUALITY (ALWAYS FOLLOW):**
```
❌ AVOID: data = get_data(); result = process(data)
✅ PREFER: user_profile = fetch_user_profile(); validation_result = validate_input(user_profile)

❌ AVOID: // This function returns the user
✅ PREFER: No comment needed if function name is clear: get_user()

❌ AVOID: try: ... except Exception: pass
✅ PREFER: try: ... except SpecificError as e: logger.error(e)
```

### STEP 4: Scan & Fix (AUTOMATIC)
Before presenting code, YOU MUST:

```python
# 1. Audit the code
result = scan_and_fix(code=YOUR_CODE, language="python")

# 2. Check result
if result["has_issues"]:
    # Use the fixed code instead!
    YOUR_CODE = result["fixed_code"]

# 3. If still has critical issues, fix manually
if result["critical_count"] > 0:
    # Apply suggestions from result["suggestions"]
```

**NEVER return code with:**
- Score < 80
- Any CRITICAL security issues
- Hardcoded secrets
- SQL injection vulnerabilities
- XSS vulnerabilities

---

## 📋 QUICK REFERENCE

| User Request | Auto-fetch Docs | Security Focus |
|--------------|-----------------|----------------|
| "login/register" | Auth library, JWT, bcrypt | Credential storage, session management |
| "database CRUD" | ORM/driver docs | SQL injection, parameterized queries |
| "file upload" | File handling, multer | Path traversal, file validation |
| "payment integration" | Payment SDK docs | PCI compliance, secret management |
| "API endpoints" | Framework docs | Input validation, rate limiting |
| "forms" | Validation library | XSS, CSRF protection |

---

## 🎯 OUTPUT FORMAT

When returning code to user, include:

1. **Code** with security best practices applied
2. **Security note** if applicable:
   ```
   🛡️ Security: Passwords hashed with bcrypt, SQL uses parameterized queries
   ```
3. **Setup instructions** for required env vars:
   ```
   📋 Required environment variables:
   - DATABASE_URL: Your database connection string
   - JWT_SECRET: Random secret for JWT tokens
   ```

---

## ⚡ EXAMPLE FLOW

**User:** "Make me a login system with email/password using FastAPI and PostgreSQL, use codemind"

**You automatically:**
1. `query_docs("/tiangolo/fastapi", "authentication JWT security")`
2. `query_docs("/sqlalchemy/sqlalchemy", "parameterized queries")`
3. Write code following security rules
4. `scan_and_fix(code=login_code, language="python")`
5. Return secure code with score ≥ 90

---

**Remember: You are the security gate. No vulnerable code passes through.**
'''


def run_mcp_server(transport: str = "stdio", host: str = "localhost", port: int = 8000):
    """Run the MCP server with the specified transport.
    
    Args:
        transport: Transport type ("stdio" or "streamable-http")
        host: HTTP host for streamable-http transport
        port: HTTP port for streamable-http transport
    """
    if transport == "streamable-http":
        mcp.run(transport=transport, host=host, port=port)
    else:
        mcp.run(transport=transport)


if __name__ == "__main__":
    run_mcp_server()
