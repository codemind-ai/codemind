"""Git diff extraction module.

Extracts and parses unified diffs from git repositories.
"""

import subprocess
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class FileDiff:
    """Represents a diff for a single file."""
    path: str
    old_path: Optional[str] = None  # For renames
    additions: int = 0
    deletions: int = 0
    is_binary: bool = False
    is_new: bool = False
    is_deleted: bool = False
    is_renamed: bool = False
    diff_text: str = ""


@dataclass
class DiffResult:
    """Represents the complete diff result."""
    files: list[FileDiff] = field(default_factory=list)
    total_additions: int = 0
    total_deletions: int = 0
    total_files: int = 0
    raw_diff: str = ""
    
    @property
    def total_lines(self) -> int:
        return self.total_additions + self.total_deletions
    
    @property
    def is_empty(self) -> bool:
        return self.total_files == 0


class DiffExtractor:
    """Extracts git diffs from a repository."""
    
    # Max lines before warning (configurable)
    DEFAULT_MAX_LINES = 5000
    
    # Patterns for parsing diff output
    FILE_HEADER_PATTERN = re.compile(r'^diff --git a/(.*) b/(.*)$')
    BINARY_PATTERN = re.compile(r'^Binary files .* differ$')
    NEW_FILE_PATTERN = re.compile(r'^new file mode')
    DELETED_FILE_PATTERN = re.compile(r'^deleted file mode')
    RENAME_PATTERN = re.compile(r'^rename from (.*)$')
    HUNK_PATTERN = re.compile(r'^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@')
    
    def __init__(self, repo_path: Optional[Path] = None, max_lines: int = DEFAULT_MAX_LINES):
        self.repo_path = repo_path or Path.cwd()
        self.max_lines = max_lines
    
    def _run_git(self, *args: str) -> tuple[str, int]:
        """Run a git command and return output + return code."""
        try:
            result = subprocess.run(
                ["git"] + list(args),
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace"
            )
            return result.stdout, result.returncode
        except FileNotFoundError:
            raise RuntimeError("Git is not installed or not in PATH")
    
    def get_diff(self, base: Optional[str] = None, head: str = "HEAD") -> DiffResult:
        """
        Extract diff between base and head.
        
        Args:
            base: Base ref to diff against (default: auto-detect upstream)
            head: Head ref (default: HEAD)
        
        Returns:
            DiffResult with parsed diff information
        """
        if base is None:
            base = self._detect_base()
        
        # Get the raw diff
        raw_diff, code = self._run_git("diff", f"{base}...{head}", "--unified=3")
        
        if code != 0:
            # Try without the triple-dot (for when base doesn't exist on remote)
            raw_diff, code = self._run_git("diff", f"{base}..{head}", "--unified=3")
        
        if code != 0:
            # Last resort: diff against base directly
            raw_diff, code = self._run_git("diff", base, head)
        
        return self._parse_diff(raw_diff)
    
    def get_staged_diff(self) -> DiffResult:
        """Get diff of staged changes only."""
        raw_diff, _ = self._run_git("diff", "--cached", "--unified=3")
        return self._parse_diff(raw_diff)
    
    def get_unstaged_diff(self) -> DiffResult:
        """Get diff of unstaged changes only."""
        raw_diff, _ = self._run_git("diff", "--unified=3")
        return self._parse_diff(raw_diff)
    
    def _detect_base(self) -> str:
        """Auto-detect the base branch for comparison."""
        # Try to get upstream branch
        upstream, code = self._run_git("rev-parse", "--abbrev-ref", "@{upstream}")
        if code == 0 and upstream.strip():
            return upstream.strip()
        
        # Fallback to common defaults
        for default in ["origin/main", "origin/master", "main", "master"]:
            _, code = self._run_git("rev-parse", "--verify", default)
            if code == 0:
                return default
        
        # Last resort: first commit
        return "HEAD~1"
    
    def _parse_diff(self, raw_diff: str) -> DiffResult:
        """Parse raw git diff output into structured format."""
        result = DiffResult(raw_diff=raw_diff)
        
        if not raw_diff.strip():
            return result
        
        lines = raw_diff.split('\n')
        current_file: Optional[FileDiff] = None
        current_diff_lines: list[str] = []
        
        for line in lines:
            # New file header
            file_match = self.FILE_HEADER_PATTERN.match(line)
            if file_match:
                # Save previous file
                if current_file:
                    current_file.diff_text = '\n'.join(current_diff_lines)
                    result.files.append(current_file)
                
                # Start new file
                old_path, new_path = file_match.groups()
                current_file = FileDiff(path=new_path)
                if old_path != new_path:
                    current_file.old_path = old_path
                    current_file.is_renamed = True
                current_diff_lines = [line]
                continue
            
            if current_file is None:
                continue
            
            current_diff_lines.append(line)
            
            # Check for binary
            if self.BINARY_PATTERN.match(line):
                current_file.is_binary = True
                continue
            
            # Check for new/deleted
            if self.NEW_FILE_PATTERN.match(line):
                current_file.is_new = True
                continue
            
            if self.DELETED_FILE_PATTERN.match(line):
                current_file.is_deleted = True
                continue
            
            # Count additions/deletions (in hunk content)
            if line.startswith('+') and not line.startswith('+++'):
                current_file.additions += 1
            elif line.startswith('-') and not line.startswith('---'):
                current_file.deletions += 1
        
        # Don't forget the last file
        if current_file:
            current_file.diff_text = '\n'.join(current_diff_lines)
            result.files.append(current_file)
        
        # Calculate totals
        result.total_files = len(result.files)
        result.total_additions = sum(f.additions for f in result.files)
        result.total_deletions = sum(f.deletions for f in result.files)
        
        return result
    
    def filter_non_binary(self, diff_result: DiffResult) -> DiffResult:
        """Return a new DiffResult with binary files filtered out."""
        filtered_files = [f for f in diff_result.files if not f.is_binary]
        
        # Rebuild raw diff without binary files
        filtered_diff = '\n'.join(f.diff_text for f in filtered_files)
        
        return DiffResult(
            files=filtered_files,
            total_additions=sum(f.additions for f in filtered_files),
            total_deletions=sum(f.deletions for f in filtered_files),
            total_files=len(filtered_files),
            raw_diff=filtered_diff
        )
    
    def check_size_warning(self, diff_result: DiffResult) -> Optional[str]:
        """Check if diff exceeds size threshold and return warning message."""
        if diff_result.total_lines > self.max_lines:
            return (
                f"⚠️  Large diff detected: {diff_result.total_lines} lines "
                f"(threshold: {self.max_lines}). "
                f"AI review quality may be reduced."
            )
        return None


def get_diff(
    repo_path: Optional[Path] = None,
    base: Optional[str] = None,
    head: str = "HEAD",
    exclude_binary: bool = True
) -> DiffResult:
    """
    Convenience function to extract diff.
    
    Args:
        repo_path: Path to git repository (default: current directory)
        base: Base ref to diff against (default: auto-detect)
        head: Head ref (default: HEAD)
        exclude_binary: Filter out binary files (default: True)
    
    Returns:
        DiffResult with parsed diff
    """
    extractor = DiffExtractor(repo_path)
    result = extractor.get_diff(base, head)
    
    if exclude_binary:
        result = extractor.filter_non_binary(result)
    
    return result
