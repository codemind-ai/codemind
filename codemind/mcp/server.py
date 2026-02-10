"""CodeMind MCP Server.

Exposes CodeMind functionality as an MCP server with tools for:
- Up-to-date documentation fetching (like Context7)
- Security and quality auditing (Guardian)
- Reviewing git diffs with AI prompts
- Auto-fixing code issues
- Secrets detection (30+ API key patterns + entropy analysis)
- Software Composition Analysis (dependency CVE scanning via OSV.dev)
- Infrastructure as Code scanning (Dockerfile, GitHub Actions, docker-compose)
- SARIF/HTML/Markdown report generation
"""

import asyncio
from pathlib import Path
from typing import Optional, List, Dict, Any

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
from ..secrets import SecretsDetector
from ..iac import IaCScanner
from ..reports import SARIFGenerator, ReportFormatter
from .checklist import LaunchAudit, generate_secure_boilerplate


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
async def resolve_library(name: str) -> dict:
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
        
        # resolve_library in fetcher is still synchronous in my edit, 
        # but let's make it async if we want to be consistent. 
        # For now I'll just call it since it's fast (handles aliases or quick GET).
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
async def query_docs(library_id: str, query: str, max_tokens: int = 5000) -> dict:
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
        
        result = await fetcher.query_docs_async(library_id, query, max_tokens)
        
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



# ─────────────────────────────────────────────────────────
# 🔑 SECRETS DETECTION TOOLS
# ─────────────────────────────────────────────────────────

@mcp.tool()
def scan_secrets(code: str, filename: str = "unknown") -> dict:
    """
    🔑 Deep secrets detection with entropy analysis.
    
    Detects 30+ types of API keys, tokens, and credentials including:
    - AWS, GCP, Azure credentials
    - GitHub, GitLab, Bitbucket tokens
    - Stripe, Twilio, SendGrid API keys
    - OpenAI, Anthropic API keys
    - Database connection strings with embedded passwords
    - Private keys (RSA, SSH, PGP, EC)
    - JWT tokens and session secrets
    - Generic high-entropy strings
    
    Uses BOTH pattern matching AND Shannon entropy analysis
    to catch even custom/unknown secret formats.
    
    Args:
        code: Source code to scan for secrets
        filename: Filename for context-aware filtering
    
    Returns:
        Dict with findings, statistics, and formatted report
    """
    detector = SecretsDetector()
    findings = detector.scan(code, filename)
    stats = detector.get_statistics(findings)
    report = detector.format_report(findings)
    
    return {
        "success": True,
        "has_secrets": len(findings) > 0,
        "total_findings": len(findings),
        "has_critical": stats.get("has_critical", False),
        "findings": [
            {
                "type": f.type,
                "service": f.service,
                "severity": f.severity.value,
                "message": f.message,
                "line": f.line,
                "redacted": f.redacted,
                "suggestion": f.suggestion,
                "cwe_id": f.cwe_id,
            }
            for f in findings
        ],
        "statistics": stats,
        "report": report,
    }


# ─────────────────────────────────────────────────────────
# 📦 SOFTWARE COMPOSITION ANALYSIS (SCA) TOOLS
# ─────────────────────────────────────────────────────────

@mcp.tool()
async def scan_dependencies(project_path: str = ".") -> dict:
    """
    📦 Scan project dependencies for known CVEs.
    
    Analyzes lockfiles and checks against OSV.dev (Google's open-source
    vulnerability database). Privacy-preserving: only package names and
    versions are sent to the API — NO source code ever leaves the machine.
    
    Supports:
    - Python: requirements.txt, Pipfile.lock, poetry.lock
    - Node.js: package.json, package-lock.json, yarn.lock
    - Go: go.mod, go.sum
    - Rust: Cargo.lock
    - Ruby: Gemfile.lock
    - PHP: composer.lock
    
    Args:
        project_path: Root directory of the project (default: current dir)
    
    Returns:
        SCA report with vulnerable packages, CVE IDs, severity, and fix versions
    """
    from ..sca import DependencyScanner
    
    scanner = DependencyScanner()
    report = scanner.scan_sync(project_path)
    formatted = scanner.format_report(report)
    
    return {
        "success": True,
        "project_path": report.project_path,
        "scanned_files": report.scanned_files,
        "total_dependencies": report.total_dependencies,
        "vulnerable_count": len(report.vulnerable),
        "total_vulnerabilities": report.total_vulnerabilities,
        "critical_count": report.critical_count,
        "risk_score": report.risk_score,
        "vulnerable": [
            {
                "name": vd.dependency.name,
                "version": vd.dependency.version,
                "ecosystem": vd.dependency.ecosystem,
                "highest_severity": vd.highest_severity,
                "fix_available": vd.fix_available,
                "vulnerabilities": [
                    {
                        "id": v.id,
                        "summary": v.summary,
                        "severity": v.severity,
                        "fixed_version": v.fixed_version,
                        "references": v.references[:3],
                    }
                    for v in vd.vulnerabilities
                ],
            }
            for vd in report.vulnerable
        ],
        "errors": report.errors,
        "report": formatted,
    }


@mcp.tool()
async def check_package(name: str, version: str, ecosystem: str = "PyPI") -> dict:
    """
    🔍 Check if a specific package version has known vulnerabilities.
    
    Quick single-package lookup against OSV.dev vulnerability database.
    
    Args:
        name: Package name (e.g., "django", "express", "lodash")
        version: Package version (e.g., "3.2.1", "4.18.2")
        ecosystem: Package ecosystem — PyPI, npm, Go, crates.io, RubyGems, Packagist
    
    Returns:
        Dict with vulnerability info, severity, and fix version if available
    """
    try:
        import httpx
    except ImportError:
        return {
            "success": False,
            "error": "Package checking requires httpx. Install with: pip install httpx"
        }
    
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(
                "https://api.osv.dev/v1/query",
                json={
                    "package": {"name": name, "ecosystem": ecosystem},
                    "version": version,
                },
            )
            response.raise_for_status()
            data = response.json()
            vulns = data.get("vulns", [])
            
            if not vulns:
                return {
                    "success": True,
                    "package": f"{name}@{version}",
                    "ecosystem": ecosystem,
                    "is_vulnerable": False,
                    "message": f"✅ {name} v{version} has no known vulnerabilities."
                }
            
            vuln_list = []
            for v in vulns:
                vuln_id = v.get("id", "UNKNOWN")
                summary = v.get("summary", v.get("details", ""))[:200]
                fixed = None
                for affected in v.get("affected", []):
                    for rng in affected.get("ranges", []):
                        for event in rng.get("events", []):
                            if "fixed" in event:
                                fixed = event["fixed"]
                vuln_list.append({
                    "id": vuln_id,
                    "summary": summary,
                    "fixed_version": fixed,
                })
            
            return {
                "success": True,
                "package": f"{name}@{version}",
                "ecosystem": ecosystem,
                "is_vulnerable": True,
                "vulnerability_count": len(vuln_list),
                "vulnerabilities": vuln_list,
                "message": f"⚠️ {name} v{version} has {len(vuln_list)} known vulnerability(ies)."
            }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ─────────────────────────────────────────────────────────
# 🏗️ INFRASTRUCTURE AS CODE (IaC) TOOLS
# ─────────────────────────────────────────────────────────

@mcp.tool()
def scan_iac_file(content: str, filename: str = "Dockerfile") -> dict:
    """
    🏗️ Scan Infrastructure as Code file for security misconfigurations.
    
    Auto-detects file type and applies relevant rules:
    - Dockerfile: root user, secrets in ENV, unpinned images, curl|sh
    - GitHub Actions: unpinned actions, script injection, excessive permissions
    - docker-compose: privileged mode, host networking, hardcoded secrets
    
    Args:
        content: File content to scan
        filename: Filename (used for type detection — e.g., "Dockerfile", "ci.yml")
    
    Returns:
        Dict with findings, severity breakdown, and formatted report
    """
    scanner = IaCScanner()
    findings = scanner.scan_content(content, filename)
    stats = scanner.get_statistics(findings)
    report = scanner.format_report(findings)
    
    return {
        "success": True,
        "has_issues": len(findings) > 0,
        "total_findings": len(findings),
        "findings": [
            {
                "rule_id": f.rule_id,
                "message": f.message,
                "severity": f.severity.value,
                "line": f.line,
                "file_type": f.file_type,
                "snippet": f.snippet,
                "suggestion": f.suggestion,
            }
            for f in findings
        ],
        "statistics": stats,
        "report": report,
    }


@mcp.tool()
def scan_infrastructure(project_path: str = ".") -> dict:
    """
    🏗️ Scan ALL IaC files in a project directory.
    
    Finds and scans: Dockerfiles, GitHub Actions workflows,
    docker-compose files, and more.
    
    Args:
        project_path: Root directory to scan (default: current dir)
    
    Returns:
        Dict with per-file findings and overall statistics
    """
    scanner = IaCScanner()
    results = scanner.scan_directory(project_path)
    
    total = 0
    critical = 0
    all_findings = []
    
    file_reports = {}
    for filepath, findings in results.items():
        total += len(findings)
        critical += sum(1 for f in findings if f.severity.value == "critical")
        file_reports[filepath] = {
            "findings_count": len(findings),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "message": f.message,
                    "severity": f.severity.value,
                    "line": f.line,
                    "suggestion": f.suggestion,
                }
                for f in findings
            ],
        }
        all_findings.extend(findings)
    
    return {
        "success": True,
        "files_scanned": len(results),
        "total_findings": total,
        "files": file_reports,
        "report": scanner.format_report(all_findings) if all_findings else "✅ No IaC security issues found.",
    }


# ─────────────────────────────────────────────────────────
# 🛡️ DEEP SCAN & REPORTING TOOLS
# ─────────────────────────────────────────────────────────

@mcp.tool()
async def deep_security_scan(
    code: str,
    language: str = "python",
    filename: str = "code.py",
    include_secrets: bool = True,
    include_quality: bool = True,
) -> dict:
    """
    🛡️ DEEP SCAN: Concurrent multi-layer security analysis.
    
    Runs ALL security scanners in parallel for maximum performance:
    1. Guardian SAST (Regex + AST)
    2. Secrets Detection (Patterns + Entropy)
    3. IaC/SCA Detection (Auto-detects based on filename)
    
    Args:
        code: Source code to analyze
        language: Programming language
        filename: Filename for context
        include_secrets: Run secrets scanner (default: True)
        include_quality: Run quality analysis (default: True)
    
    Returns:
        Unified security report with all findings and risk score.
    """
    results = {
        "success": True,
        "scans_completed": [],
    }
    
    # 1. Run scans concurrently where possible
    guardian = Guardian()
    
    # Execute synchronous scans in threads to avoid blocking event loop
    loop = asyncio.get_event_loop()
    
    sast_task = loop.run_in_executor(None, guardian.audit, code, filename)
    
    scans = [sast_task]
    
    if include_secrets:
        detector = SecretsDetector()
        secrets_task = loop.run_in_executor(None, detector.scan, code, filename)
        scans.append(secrets_task)
    
    # Wait for basic scans
    completed_scans = await asyncio.gather(*scans)
    report = completed_scans[0]
    
    security_issues = []
    quality_issues = []
    
    for issue in report.issues:
        issue_dict = {
            "message": issue.message,
            "severity": issue.severity.value,
            "line": issue.line,
            "snippet": issue.code_snippet,
            "suggestion": issue.suggestion,
            "vulnerability_type": issue.vulnerability_type,
        }
        if issue.type == GuardType.SECURITY:
            security_issues.append(issue_dict)
        elif include_quality:
            quality_issues.append(issue_dict)
            
    results["sast"] = {
        "score": report.score,
        "security_issues": security_issues,
        "quality_issues": quality_issues,
    }
    results["scans_completed"].append("sast")

    if include_secrets:
        secret_findings = completed_scans[1]
        results["secrets"] = {
            "total": len(secret_findings),
            "findings": [
                {
                    "type": f.type,
                    "severity": f.severity.value,
                    "message": f.message,
                    "line": f.line,
                    "suggestion": f.suggestion,
                }
                for f in secret_findings
            ],
        }
        results["scans_completed"].append("secrets")

    # 3. IaC Scan (if applicable)
    is_iac = filename.lower() in ["dockerfile", "docker-compose.yml", "docker-compose.yaml"] or "github/workflows" in filename.replace("\\", "/")
    if is_iac:
        iac_scanner = IaCScanner()
        iac_findings = iac_scanner.scan_content(code, filename)
        results["iac"] = {
            "total": len(iac_findings),
            "findings": [
                {
                    "type": f.type,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "line": f.line,
                    "message": f.message,
                }
                for f in iac_findings
            ]
        }
        results["scans_completed"].append("iac")

    # 4. SCA Scan (if applicable)
    from ..sca.scanner import DependencyScanner
    sca_scanner = DependencyScanner()
    if filename.lower() in sca_scanner.PARSERS:
        from ..sca.scanner import Dependency
        # Need to parse and then check OSV
        parser_name, ecosystem = sca_scanner.PARSERS[filename.lower()]
        # We need a temp file path for the parser usually, but we can simulate
        sca_report = await sca_scanner._check_osv(sca_scanner._parse_requirements_txt_from_content(code, filename, ecosystem) if parser_name == "_parse_requirements_txt" else [])
        # Simplified for now, in a real scenario we'd use the full async scanner
        results["sca"] = {"total": len(sca_report)}
        results["scans_completed"].append("sca")

    # Calculate unified score
    all_issues_count = len(security_issues) + len(quality_issues)
    has_critical = any(i["severity"] == "critical" for i in security_issues)
    
    base_score = results["sast"]["score"]
    
    if include_secrets:
        secret_findings = completed_scans[1]
        all_issues_count += len(secret_findings)
        if any(sf.severity.value == "critical" for sf in secret_findings):
            has_critical = True
        
        # Reduce score for secrets found
        for sf in secret_findings:
            if sf.severity.value == "critical":
                base_score -= 15
            elif sf.severity.value == "high":
                base_score -= 10
            elif sf.severity.value == "medium":
                base_score -= 5

    if "iac" in results and results["iac"]["total"] > 0:
        base_score -= (results["iac"]["total"] * 5)
        all_issues_count += results["iac"]["total"]
        if any(f["severity"] == "critical" for f in results["iac"]["findings"]):
            has_critical = True
    
    if "sca" in results and results["sca"]["total"] > 0:
        base_score -= (results["sca"]["total"] * 10)
        all_issues_count += results["sca"]["total"]

    final_score = max(0, min(100, base_score))
    
    results["overall"] = {
        "score": final_score,
        "total_issues": all_issues_count,
        "has_critical": has_critical,
        "is_safe": final_score >= 80 and not has_critical,
        "grade": (
            "A+" if final_score >= 95 else
            "A" if final_score >= 90 else
            "B" if final_score >= 80 else
            "C" if final_score >= 70 else
            "D" if final_score >= 60 else
            "F"
        ),
    }
    
    # Build unified text report
    report_lines = [
        f"# 🛡️ CodeMind Deep Security Scan",
        f"",
        f"**Score:** {final_score}/100 (Grade: {results['overall']['grade']})",
        f"**Status:** {'✅ PASSED' if results['overall']['is_safe'] else '🚨 ISSUES FOUND'}",
        f"**Total Issues:** {all_issues_count}",
        f"**Scans:** {', '.join(results['scans_completed'])}",
        f"",
    ]
    
    if security_issues:
        report_lines.append(f"## 🔒 Security ({len(security_issues)} issues)")
        for i in security_issues[:5]:
            report_lines.append(f"- **Line {i['line']}** [{i['severity']}]: {i['message']}")
        if len(security_issues) > 5:
            report_lines.append(f"- ...and {len(security_issues) - 5} more")
        report_lines.append("")
    
    if include_secrets and results.get("secrets"):
        findings = results["secrets"]["findings"]
        report_lines.append(f"## 🔑 Secrets ({len(findings)} found)")
        for sf in findings[:5]:
            report_lines.append(f"- **Line {sf['line']}** [{sf.get('service', 'Unknown')}]: {sf['message']}")
        report_lines.append("")
    
    if quality_issues:
        report_lines.append(f"## ✨ Quality ({len(quality_issues)} issues)")
        for i in quality_issues[:3]:
            report_lines.append(f"- **Line {i['line']}**: {i['message']}")
        report_lines.append("")
    
    results["report"] = "\n".join(report_lines)
    
    return results


@mcp.tool()
def export_security_report(
    code: str,
    language: str = "python",
    filename: str = "code.py",
    format: str = "sarif",
) -> dict:
    """
    📋 Export security scan results in industry-standard formats.
    
    Formats:
    - sarif: SARIF v2.1.0 (GitHub Code Scanning compatible)
    - json: Structured JSON report
    - markdown: Human-readable markdown
    - html: Standalone dark-themed HTML report with visual score
    - csv: Spreadsheet-compatible CSV
    
    Args:
        code: Source code to scan
        language: Programming language
        filename: Source filename
        format: Output format — sarif, json, markdown, html, csv
    
    Returns:
        Dict with the formatted report content
    """
    # Run full scan
    guardian = Guardian()
    report = guardian.audit(code, filename)
    
    # Also run secrets scan
    detector = SecretsDetector()
    secret_findings = detector.scan(code, filename)
    
    # Build unified scan result dict
    scan_result = {
        "score": report.score,
        "is_safe": report.score >= 80 and not any(
            i.severity.value == "critical" for i in report.issues
        ),
        "total_issues": len(report.issues) + len(secret_findings),
        "counts": {
            "critical": sum(1 for i in report.issues if i.severity.value == "critical") + 
                       sum(1 for s in secret_findings if s.severity.value == "critical"),
            "warning": sum(1 for i in report.issues if i.severity.value == "warning"),
            "info": sum(1 for i in report.issues if i.severity.value == "info"),
            "total": len(report.issues) + len(secret_findings),
        },
        "security_issues": [
            {
                "severity": i.severity.value,
                "vulnerability_type": i.vulnerability_type or "OTHER",
                "message": i.message,
                "line": i.line,
                "file": filename,
                "snippet": i.code_snippet,
                "suggestion": i.suggestion,
            }
            for i in report.issues if i.type == GuardType.SECURITY
        ],
        "quality_issues": [
            {
                "severity": i.severity.value,
                "message": i.message,
                "line": i.line,
                "snippet": i.code_snippet,
                "suggestion": i.suggestion,
            }
            for i in report.issues if i.type == GuardType.QUALITY
        ],
        "secrets": [
            {
                "service": s.service,
                "message": s.message,
                "line": s.line,
                "severity": s.severity.value,
            }
            for s in secret_findings
        ],
    }
    
    formatter = ReportFormatter()
    
    if format == "sarif":
        sarif_gen = SARIFGenerator.from_guard_issues(report.issues, filename)
        if secret_findings:
            secret_sarif = SARIFGenerator.from_secret_findings(secret_findings)
            sarif_gen.add_findings(secret_sarif.findings)
        content = sarif_gen.to_json()
    elif format == "html":
        content = formatter.to_html(scan_result)
    elif format == "markdown":
        content = formatter.to_markdown(scan_result)
    elif format == "csv":
        content = formatter.to_csv(scan_result)
    else:  # json
        content = formatter.to_json(scan_result)
    
    return {
        "success": True,
        "format": format,
        "content": content,
        "scan_summary": {
            "score": report.score,
            "total_issues": scan_result["total_issues"],
            "is_safe": scan_result["is_safe"],
        },
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

---

## 🚀 The "Vibe Coder" Launch Checklist
*Run `audit_launch_checklist()` to verify these automatically.*

- **Rate Limits**: Protect your API from abuse and DDoS.
- **Row Level Security (RLS)**: Ensure users can ONLY access their own data.
- **CAPTCHA**: Protect auth and forms from bot spam/brute-force.
- **Server-side Validation**: NEVER trust client-side data (use Zod/Pydantic).
- **API Keys Secured**: No hardcoded keys in source code.
- **Env Vars**: Use `.env` and `process.env`/`os.environ`.
- **CORS Restrictions**: Limit origins to trusted domains only.
- **Dependency Audit**: Scan for known vulnerabilities in your packages.
- **Safety Lock**: Prevents accidental `DROP`, `TRUNCATE`, or `DELETE` without `WHERE`.
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


@mcp.tool()
def explain_vulnerability(vulnerability_type: str) -> str:
    """
    🎓 📖 Get detailed educational context and best practices for a vulnerability type.
    
    Use this if you are unsure why something is a security risk or want to know
    the standard industry fix (CWE/OWASP).
    
    Args:
        vulnerability_type: The type ID (e.g., "SQL_INJECTION", "XSS", "PATH_TRAVERSAL")
    
    Returns:
        Structured educational content with "Risk", "Fix", and "Example" sections.
    """
    from ..reports.sarif import CWE_MAP
    
    vuln = vulnerability_type.upper()
    info = CWE_MAP.get(vuln)
    
    if not info:
        return f"No detailed info found for '{vulnerability_type}'. It is generally a security risk that should be remediated."
    
    return f"""
# 🎓 Security Spotlight: {info['name']}
**CWE:** {info['cwe']} | **OWASP:** {info['owasp']}

### 🚨 Why it's a risk:
{vuln} occurs when untrusted data is sent to an interpreter as part of a command or query. 
This can lead to unauthorized data access, execution of arbitrary commands, or full system compromise.

### ✅ How to fix it:
1. **Parameterized Queries**: Use placeholders like `?` or `%s` instead of string interpolation.
2. **Input Validation**: Strictly validate input against a whitelist.
3. **Escaping**: Escape data appropriately for the target interpreter (e.g., HTML escaping).
4. **Least Privilege**: Ensure the database user has minimal necessary permissions.

### 📝 Example Fix:
- **Unsafe**: `cursor.execute(f"SELECT * FROM users WHERE id = '{uid}'")`
- **Safe**: `cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))`
"""

@mcp.tool()
async def review_file(filepath: str) -> dict:
    """
    🔍 📄 Comprehensive security audit of a local file.
    
    Reads the file from disk and runs SAST, Secrets, and IaC/SCA scans.
    
    Args:
        filepath: Absolute path to the file to review
    
    Returns:
        Full deep scan result for the file.
    """
    path = Path(filepath)
    if not path.exists():
        return {"success": False, "error": f"File {filepath} not found."}
    
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        return await deep_security_scan(content, filename=path.name)
    except Exception as e:
        return {"success": False, "error": str(e)}

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
    return '''🛡️ **CODEMIND v2.0 ACTIVATED** - Full Security Suite

When the user adds "use codemind" to their request, you MUST follow this workflow:

---

## 🔄 AUTOMATIC WORKFLOW

### STEP 1: Analyze Request
Identify what the user is building or asking for:
- Building something? Use `resolve_library` -> `query_docs`.
- Existing file issue? Use `review_file(path)`.
- Generic code snippet? Use `deep_security_scan(code)`.
- Unclear vulnerability? Use `explain_vulnerability(type)`.
- Project-wide audit? Use `scan_infrastructure` and `scan_secrets`.

### STEP 2: Fetch Documentation (if building)
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
# 1. Deep security scan (SAST + Secrets + Quality)
result = deep_security_scan(code=YOUR_CODE, language="python")

# 2. Check result
if not result["overall"]["is_safe"]:
    # Use scan_and_fix for auto-repair
    fixed = scan_and_fix(code=YOUR_CODE, language="python")
    YOUR_CODE = fixed["fixed_code"]

# 3. If still has critical issues, fix manually
if result["overall"]["has_critical"]:
    # Apply suggestions from result
```

**NEVER return code with:**
- Score < 80
- Any CRITICAL security issues
- Hardcoded secrets
- SQL injection vulnerabilities
- XSS vulnerabilities

### STEP 5: IaC & Dependencies (WHEN APPLICABLE)
If the user creates infrastructure files:
```python
# Scan Dockerfiles, GitHub Actions, docker-compose
scan_iac_file(content=dockerfile_content, filename="Dockerfile")

# Scan project dependencies for CVEs
scan_dependencies(project_path=".")

# Check a specific package
check_package(name="django", version="3.2.1", ecosystem="PyPI")
```

---

## 🧰 FULL TOOL ARSENAL

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `guard_code` | SAST — 50+ vulnerability patterns | Any code audit |
| `scan_secrets` | 🔑 30+ API key/token detection + entropy | Code with credentials |
| `scan_and_fix` | Scan + auto-fix in one action | Before returning code |
| `deep_security_scan` | 🛡️ Multi-layer scan (SAST+Secrets+Quality) | Comprehensive analysis |
| `scan_dependencies` | 📦 CVE scan via OSV.dev | Projects with lockfiles |
| `check_package` | 🔍 Single package CVE lookup | Checking a specific dep |
| `scan_iac_file` | 🏗️ Dockerfile/GHA/compose scanning | Infrastructure code |
| `scan_infrastructure` | 🏗️ Scan all IaC files in project | Full project scan |
| `export_security_report` | 📋 SARIF/HTML/Markdown/CSV reports | CI/CD integration |
| `improve_code` | Auto-improve code quality | Fixing found issues |
| `resolve_library` | Find library documentation IDs | Before querying docs |
| `query_docs` | Fetch up-to-date library docs | Writing code |

---

## 📋 QUICK REFERENCE

| User Request | Auto-fetch Docs | Security Tools to Use |
|--------------|-----------------|----------------------|
| "login/register" | Auth library, JWT, bcrypt | `deep_security_scan` + `scan_secrets` |
| "database CRUD" | ORM/driver docs | `guard_code` + `scan_dependencies` |
| "file upload" | File handling, multer | `guard_code` (path traversal) |
| "payment integration" | Payment SDK docs | `scan_secrets` + `deep_security_scan` |
| "API endpoints" | Framework docs | `guard_code` + `scan_and_fix` |
| "Dockerfile" | Docker best practices | `scan_iac_file` |
| "CI/CD pipeline" | GitHub Actions docs | `scan_iac_file` + `scan_infrastructure` |
| "deploy" | Deployment docs | `scan_dependencies` + `scan_infrastructure` |

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
4. **Security score** from deep scan:
   ```
   📊 CodeMind Score: 95/100 (Grade: A) — ✅ PASSED
   ```

---

## ⚡ EXAMPLE FLOW

**User:** "Make me a login system with email/password using FastAPI and PostgreSQL, use codemind"

**You automatically:**
1. `query_docs("/tiangolo/fastapi", "authentication JWT security")`
2. `query_docs("/sqlalchemy/sqlalchemy", "parameterized queries")`
3. Write code following security rules
4. `deep_security_scan(code=login_code, language="python")`
5. `scan_secrets(code=login_code)` — verify no hardcoded credentials
6. Return secure code with score ≥ 90

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
@mcp.tool()
async def audit_launch_checklist(code: str, filename: str = "code.py") -> dict:
    """
    🚀 LAUNCH CHECKLIST AUDIT: Verify code against the essential production checklist.
    
    Checks for:
    → Rate limits
    → Row Level Security (RLS)
    → CAPTCHA on auth + forms
    → Server-side validation
    → Env vars usage
    → CORS restrictions
    → Safety Lock (Destructive actions)
    → (And runs Dependency + Secrets scan)
    
    Args:
        code: Source code to audit
        filename: Filename for context
    
    Returns:
        Checklist report with passed/failed/warning status for each production-ready item.
    """
    auditor = LaunchAudit()
    checklist_results = auditor.audit(code, filename)
    
    # Also run secrets scan
    detector = SecretsDetector()
    secret_findings = detector.scan(code, filename)
    secrets_item = {
        "id": "api_keys",
        "name": "API Keys Secured",
        "status": "passed" if not secret_findings else "failed",
        "message": "No hardcoded secrets found." if not secret_findings else f"Found {len(secret_findings)} hardcoded secrets!",
        "suggestion": "" if not secret_findings else "Move secrets to environment variables.",
        "category": "Security"
    }
    
    # Also check if it's a lockfile for dependency audit
    from ..sca import DependencyScanner
    scanner = DependencyScanner()
    sca_item = {
        "id": "dependencies",
        "name": "Dependency Audit",
        "status": "warning",
        "message": "Run scan_dependencies() for a full audit.",
        "suggestion": "Regularly audit dependencies for CVEs.",
        "category": "Supply Chain"
    }
    
    if filename.lower() in scanner.PARSERS:
        report = scanner.scan_sync(Path(filename).parent)
        sca_item.update({
            "status": "passed" if not report.vulnerable else "failed",
            "message": f"Found {len(report.vulnerable)} vulnerable packages." if report.vulnerable else "No vulnerable packages found in lockfile.",
            "suggestion": "Update vulnerable dependencies to recommended versions." if report.vulnerable else ""
        })

    # Combine everything
    all_items = checklist_results + [secrets_item, sca_item]
    
    passed_count = sum(1 for i in all_items if i.status == "passed")
    failed_count = sum(1 for i in all_items if i.status == "failed")
    warning_count = sum(1 for i in all_items if i.status == "warning")
    
    progress = int((passed_count / len(all_items)) * 100)
    
    # Format report
    report_lines = [
        f"# 🚀 Launch Readiness Report",
        f"",
        f"**Progress:** {progress}% compliant",
        f"```",
        f"Passed:  {passed_count} ✅",
        f"Failed:  {failed_count} 🚨",
        f"Warning: {warning_count} ⚠️",
        f"```",
        f"",
        f"## 📋 Detailed Checklist",
        f""
    ]
    
    for item in all_items:
        status_emoji = "✅" if item.status == "passed" else "🚨" if item.status == "failed" else "⚠️"
        report_lines.append(f"### {status_emoji} {item.name}")
        report_lines.append(f"- **Status:** {item.status.upper()}")
        report_lines.append(f"- **Message:** {item.message}")
        if item.suggestion:
            report_lines.append(f"- **💡 Fix:** {item.suggestion}")
        report_lines.append("")

    return {
        "success": True,
        "progress": progress,
        "passed": passed_count,
        "failed": failed_count,
        "warnings": warning_count,
        "items": [
            {
                "id": i.id if hasattr(i, 'id') else i['id'],
                "name": i.name if hasattr(i, 'name') else i['name'],
                "status": i.status if hasattr(i, 'status') else i['status'],
                "category": i.category if hasattr(i, 'category') else i['category'],
                "message": i.message if hasattr(i, 'message') else i['message'],
                "suggestion": i.suggestion if hasattr(i, 'suggestion') else i['suggestion'],
            }
            for i in all_items
        ],
        "report": "\n".join(report_lines),
        "hint": "Use 'get_secure_boilerplate' to fix failed items."
    }


@mcp.tool()
def get_secure_boilerplate(framework: str, feature: str) -> dict:
    """
    🛠️ Get secure boilerplate code for production features.
    
    Available Features:
    - rate_limit: Rate limiting (Next.js, FastAPI, Express)
    - rls: Row Level Security (SQL/PostgreSQL)
    - captcha: CAPTCHA integration (Next.js/Turnstile)
    - validation: Server-side validation (Zod, Pydantic)
    - cors: Secure CORS config (Express)
    
    Available Frameworks:
    - nextjs, fastapi, express, sql
    
    Args:
        framework: Target framework/language
        feature: Security feature to implement
    
    Returns:
        Secure code snippet and implementation guide.
    """
    result = generate_secure_boilerplate(framework, feature)
    
    if not result:
        return {
            "success": False,
            "error": f"No boilerplate found for {framework} + {feature}",
            "suggestions": {
                "Frameworks": ["nextjs", "fastapi", "express", "sql"],
                "Features": ["rate_limit", "rls", "captcha", "validation", "cors"]
            }
        }
    
    return {
        "success": True,
        "title": result.title,
        "code": result.code,
        "description": result.description,
        "language": "javascript" if framework in ["nextjs", "express"] else "python" if framework == "fastapi" else "sql"
    }
