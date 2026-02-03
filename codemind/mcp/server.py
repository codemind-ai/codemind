"""CodeMind MCP Server.

Exposes CodeMind functionality as an MCP server with tools for:
- Reviewing git diffs with AI prompts
- Managing review history
- Validating AI response output
"""

from pathlib import Path
from typing import Optional

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
from ..llm.fixer import CodeFixer
from ..llm import get_llm_provider
from ..config import load_config


# Initialize MCP Server
mcp = FastMCP(
    "CodeMind",
    version="0.1.0",
)


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


@mcp.tool()
def guard_code(code: str, language: str = "python", filename: str = "snippet.code") -> dict:
    """
    Perform a security and quality audit on a code snippet.
    
    Checks for security vulnerabilities, 'AI slop', and clean code violations.
    
    Args:
        code: The code content to audit
        language: Programming language (python, javascript, etc.)
        filename: Optional filename for context
    
    Returns:
        Audit report including security score and list of issues
    """
    guardian = Guardian()
    report = guardian.audit(code, filename)
    
    issues_list = [
        {
            "type": issue.type.value,
            "severity": issue.severity.value,
            "message": issue.message,
            "line": issue.line,
            "snippet": issue.code_snippet
        }
        for issue in report.issues
    ]
    
    return {
        "success": True,
        "score": report.score,
        "is_safe": report.is_safe,
        "is_clean": report.is_clean,
        "issues": issues_list,
        "summary": f"Audit complete. Score: {report.score}/100. Found {len(issues_list)} issues."
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


@mcp.resource("guardian://best-practices")
def guardian_best_practices() -> str:
    """Get security and clean code best practices."""
    return """CodeMind Guardian - Best Practices
=================================

Security:
1. Never hardcode secrets (passwords, keys, tokens). Use env vars.
2. Sanitize all user input before using it in database queries or HTML.
3. Avoid dangerous functions like eval(), exec(), or innerHTML with untrusted data.
4. Use safe deserialization (e.g., yaml.safe_load instead of yaml.load).

Clean Code & AI Slop Prevention:
1. Names should be descriptive. Avoid generic names like 'data' or 'result'.
2. Comments should explain 'why', not 'what'. Avoid redundant comments.
3. Keep functions focused on a single responsibility (SRP).
4. Remove debugging statements (print, console.log) before commit.
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
    Activate the full CodeMind Guardian suite for security, quality, and clean code.
    Use this to ensure your code is professional, safe, and free of 'AI slop'.
    """
    return """You have activated CodeMind Guardian. From now on, you must ensure that every piece of code you generate or modify meets the highest standards of security and cleanliness.

Follow these rules:
1. **Security First**: Before finalizing any code, use the `guard_code` tool to check for vulnerabilities.
2. **No AI Slop**: Remove redundant comments (e.g., "// This function adds X"), use descriptive names, and follow SOLID/DRY principles.
3. **Verify & Improve**: If `guard_code` returns a score < 90, you MUST use it to find issues and then use the `improve_code` tool (or manually refactor) until the code is perfect.
4. **Best Practices**: Always reference `guardian://best-practices` for authoritative patterns.

Your goal is to produce code that is indistinguishable from that of a senior system architect."""


def run_server(transport: str = "stdio"):
    """Run the MCP server with the specified transport."""
    mcp.run(transport=transport)


if __name__ == "__main__":
    run_server()
