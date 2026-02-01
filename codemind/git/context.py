"""Git context detection module.

Detects branch, remote, and repository context for diff operations.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .utils import run_git_command, GitTimeoutError, GitNotFoundError


@dataclass
class GitContext:
    """Git repository context information."""
    repo_root: Path
    current_branch: str
    upstream_branch: Optional[str] = None
    remote_name: Optional[str] = None
    is_dirty: bool = False
    has_staged: bool = False
    commit_count: int = 0  # Commits ahead of upstream


class ContextDetector:
    """Detects git repository context."""
    
    def __init__(self, repo_path: Optional[Path] = None):
        self.repo_path = repo_path or Path.cwd()
    
    def _run_git(self, *args: str) -> tuple[str, int]:
        """Run a git command and return output + return code."""
        try:
            return run_git_command(*args, cwd=self.repo_path)
        except GitTimeoutError:
            raise RuntimeError(f"Git command timed out: git {' '.join(args)}")
        except GitNotFoundError:
            raise RuntimeError("Git is not installed or not in PATH")
    
    def get_context(self) -> GitContext:
        """Get full git context for the repository."""
        repo_root = self._get_repo_root()
        current_branch = self._get_current_branch()
        upstream_branch = self._get_upstream_branch()
        remote_name = self._get_remote_name()
        is_dirty = self._is_dirty()
        has_staged = self._has_staged()
        commit_count = self._get_commit_count(upstream_branch)
        
        return GitContext(
            repo_root=repo_root,
            current_branch=current_branch,
            upstream_branch=upstream_branch,
            remote_name=remote_name,
            is_dirty=is_dirty,
            has_staged=has_staged,
            commit_count=commit_count
        )
    
    def _get_repo_root(self) -> Path:
        """Get the root directory of the git repository."""
        output, code = self._run_git("rev-parse", "--show-toplevel")
        if code != 0:
            raise RuntimeError(f"Not a git repository: {self.repo_path}")
        return Path(output)
    
    def _get_current_branch(self) -> str:
        """Get the current branch name."""
        output, code = self._run_git("rev-parse", "--abbrev-ref", "HEAD")
        if code != 0:
            return "HEAD"  # Detached HEAD state
        return output
    
    def _get_upstream_branch(self) -> Optional[str]:
        """Get the upstream tracking branch."""
        output, code = self._run_git("rev-parse", "--abbrev-ref", "@{upstream}")
        if code != 0:
            return None
        return output
    
    def _get_remote_name(self) -> Optional[str]:
        """Get the remote name (usually 'origin')."""
        output, code = self._run_git("remote")
        if code != 0 or not output:
            return None
        # Return first remote
        return output.split('\n')[0]
    
    def _is_dirty(self) -> bool:
        """Check if working directory has uncommitted changes."""
        output, _ = self._run_git("status", "--porcelain")
        return bool(output)
    
    def _has_staged(self) -> bool:
        """Check if there are staged changes."""
        # --quiet returns 1 if there are differences
        _, code = self._run_git("diff", "--cached", "--quiet")
        return code != 0
    
    def _get_commit_count(self, upstream: Optional[str]) -> int:
        """Get number of commits ahead of upstream."""
        if not upstream:
            return 0
        output, code = self._run_git("rev-list", "--count", f"{upstream}..HEAD")
        if code != 0:
            return 0
        try:
            return int(output)
        except ValueError:
            return 0
    
    def get_best_base(self) -> str:
        """
        Determine the best base ref for diff comparison.
        
        Priority:
        1. Upstream branch (if set)
        2. origin/main or origin/master
        3. main or master (local)
        4. First parent commit
        """
        ctx = self.get_context()
        
        # Use upstream if available
        if ctx.upstream_branch:
            return ctx.upstream_branch
        
        # Try common remote defaults
        remote = ctx.remote_name or "origin"
        for branch in ["main", "master"]:
            ref = f"{remote}/{branch}"
            _, code = self._run_git("rev-parse", "--verify", ref)
            if code == 0:
                return ref
        
        # Try local defaults
        for branch in ["main", "master"]:
            _, code = self._run_git("rev-parse", "--verify", branch)
            if code == 0:
                return branch
        
        # Last resort: parent commit
        return "HEAD~1"


def get_context(repo_path: Optional[Path] = None) -> GitContext:
    """Convenience function to get git context."""
    return ContextDetector(repo_path).get_context()


def get_best_base(repo_path: Optional[Path] = None) -> str:
    """Convenience function to get best base ref for diffing."""
    return ContextDetector(repo_path).get_best_base()
