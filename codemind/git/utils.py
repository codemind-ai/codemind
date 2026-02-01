"""Git utility functions.

Shared utilities for git operations.
"""

import subprocess
from pathlib import Path
from typing import Optional


# Default timeout for git commands (seconds)
DEFAULT_GIT_TIMEOUT = 30


class GitError(Exception):
    """Base exception for git-related errors."""
    pass


class GitTimeoutError(GitError):
    """Raised when a git command times out."""
    pass


class GitNotFoundError(GitError):
    """Raised when git is not installed or not in PATH."""
    pass


def run_git_command(
    *args: str,
    cwd: Optional[Path] = None,
    timeout: int = DEFAULT_GIT_TIMEOUT
) -> tuple[str, int]:
    """
    Run a git command and return output + return code.
    
    Args:
        *args: Git command arguments (e.g., "status", "--porcelain")
        cwd: Working directory for the command
        timeout: Command timeout in seconds (default: 30)
    
    Returns:
        Tuple of (stdout, return_code)
    
    Raises:
        GitTimeoutError: If command times out
        GitNotFoundError: If git is not installed
    """
    try:
        result = subprocess.run(
            ["git"] + list(args),
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout
        )
        return result.stdout.strip(), result.returncode
    except subprocess.TimeoutExpired:
        raise GitTimeoutError(
            f"Git command timed out after {timeout}s: git {' '.join(args)}"
        )
    except FileNotFoundError:
        raise GitNotFoundError("Git is not installed or not in PATH")
