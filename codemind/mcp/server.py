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


def run_server(transport: str = "stdio"):
    """Run the MCP server with the specified transport."""
    mcp.run(transport=transport)


if __name__ == "__main__":
    run_server()
