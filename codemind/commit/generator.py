"""Git commit message generator module.

Generates AI-powered commit messages from staged changes.
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from ..git.utils import run_git_command, GitError


class CommitStyle(Enum):
    """Commit message styles."""
    CONVENTIONAL = "conventional"  # feat: add login feature
    SIMPLE = "simple"              # Add login feature  
    DESCRIPTIVE = "descriptive"    # Detailed multi-line commit


@dataclass
class StagedChanges:
    """Represents staged git changes."""
    diff: str
    files: list[str]
    additions: int
    deletions: int
    is_empty: bool = False
    
    @property
    def total_lines(self) -> int:
        return self.additions + self.deletions
    
    @property
    def summary(self) -> str:
        """Human-readable summary."""
        return f"{len(self.files)} files, +{self.additions}/-{self.deletions}"


def get_staged_diff(cwd: Optional[Path] = None) -> StagedChanges:
    """
    Get the diff of staged changes (ready to commit).
    
    Args:
        cwd: Working directory (default: current directory)
    
    Returns:
        StagedChanges with diff content and stats
    """
    # Get staged diff
    diff_output, code = run_git_command("diff", "--cached", cwd=cwd)
    
    if code != 0 or not diff_output.strip():
        return StagedChanges(
            diff="",
            files=[],
            additions=0,
            deletions=0,
            is_empty=True
        )
    
    # Get list of staged files
    files_output, _ = run_git_command("diff", "--cached", "--name-only", cwd=cwd)
    files = [f for f in files_output.strip().split("\n") if f]
    
    # Get stats
    stats_output, _ = run_git_command("diff", "--cached", "--stat", cwd=cwd)
    
    # Parse additions/deletions from stat
    additions = 0
    deletions = 0
    for line in stats_output.split("\n"):
        if "insertion" in line or "deletion" in line:
            parts = line.split(",")
            for part in parts:
                if "insertion" in part:
                    additions = int(''.join(c for c in part if c.isdigit()) or 0)
                elif "deletion" in part:
                    deletions = int(''.join(c for c in part if c.isdigit()) or 0)
    
    return StagedChanges(
        diff=diff_output,
        files=files,
        additions=additions,
        deletions=deletions,
        is_empty=False
    )


# Default template path
TEMPLATE_DIR = Path(__file__).parent / "templates"
DEFAULT_COMMIT_TEMPLATE = TEMPLATE_DIR / "commit.txt"


@dataclass
class CommitPromptConfig:
    """Configuration for commit prompt generation."""
    style: CommitStyle = CommitStyle.CONVENTIONAL
    max_length: int = 72  # Standard commit message line length
    include_body: bool = True
    include_scope: bool = True
    template_path: Optional[Path] = None


@dataclass 
class BuiltCommitPrompt:
    """Result of building a commit prompt."""
    content: str
    token_estimate: int
    staged_summary: str
    style: CommitStyle


class CommitPromptBuilder:
    """Builds prompts for AI commit message generation."""
    
    CHARS_PER_TOKEN = 4
    MAX_DIFF_CHARS = 30000  # Smaller than review, commits should be focused
    
    def __init__(self, config: Optional[CommitPromptConfig] = None):
        self.config = config or CommitPromptConfig()
        self.template = self._load_template()
    
    def _load_template(self) -> str:
        """Load the commit prompt template."""
        template_path = self.config.template_path or DEFAULT_COMMIT_TEMPLATE
        
        if not template_path.exists():
            # Use embedded default template
            return self._get_default_template()
        
        return template_path.read_text(encoding="utf-8")
    
    def _get_default_template(self) -> str:
        """Get the embedded default template."""
        if self.config.style == CommitStyle.CONVENTIONAL:
            return self._get_conventional_template()
        elif self.config.style == CommitStyle.SIMPLE:
            return self._get_simple_template()
        else:
            return self._get_descriptive_template()
    
    def _get_conventional_template(self) -> str:
        return """You are a commit message generator. Analyze the following git diff and generate a commit message following the Conventional Commits specification.

FORMAT:
<type>(<scope>): <subject>

<body>

TYPES (use only these):
- feat: A new feature
- fix: A bug fix
- docs: Documentation only changes
- style: Code style changes (formatting, semicolons, etc)
- refactor: Code change that neither fixes a bug nor adds a feature
- perf: Performance improvement
- test: Adding or updating tests
- chore: Maintenance tasks, dependencies, configs

RULES:
1. Subject line MUST be {max_length} characters or less
2. Subject line should be imperative mood ("add feature" not "added feature")
3. Do NOT end subject with period
4. Scope is optional but recommended (e.g., auth, api, ui)
5. Body should explain WHAT and WHY, not HOW
6. Keep body lines under 72 characters

STAGED CHANGES:
Files: {files}
Stats: {stats}

DIFF:
---
{diff_content}
---

Generate ONLY the commit message, nothing else:"""

    def _get_simple_template(self) -> str:
        return """You are a commit message generator. Analyze the following git diff and generate a simple, clear commit message.

FORMAT:
<subject line>

<optional body explaining what changed>

RULES:
1. Subject line MUST be {max_length} characters or less
2. Use imperative mood ("Add feature" not "Added feature")  
3. Capitalize the first letter
4. Do NOT end with period
5. Body is optional, use only if changes need explanation

STAGED CHANGES:
Files: {files}
Stats: {stats}

DIFF:
---
{diff_content}
---

Generate ONLY the commit message, nothing else:"""

    def _get_descriptive_template(self) -> str:
        return """You are a commit message generator. Analyze the following git diff and generate a detailed, descriptive commit message.

FORMAT:
<subject line summarizing all changes>

<detailed body explaining:>
- What was changed
- Why it was changed  
- Any important implementation details
- Breaking changes (if any)

RULES:
1. Subject line MUST be {max_length} characters or less
2. Use imperative mood
3. Body should be comprehensive but concise
4. Use bullet points for multiple changes
5. Mention file names when relevant

STAGED CHANGES:
Files: {files}
Stats: {stats}

DIFF:
---
{diff_content}
---

Generate ONLY the commit message, nothing else:"""

    def build(self, staged: StagedChanges) -> BuiltCommitPrompt:
        """
        Build a commit message prompt from staged changes.
        
        Args:
            staged: Staged changes to generate message for
            
        Returns:
            BuiltCommitPrompt with the generated prompt
        """
        diff_content = staged.diff
        
        # Truncate if too large
        if len(diff_content) > self.MAX_DIFF_CHARS:
            diff_content = diff_content[:self.MAX_DIFF_CHARS]
            diff_content += "\n\n... [diff truncated] ..."
        
        # Build file list
        files_list = ", ".join(staged.files[:10])
        if len(staged.files) > 10:
            files_list += f" (+{len(staged.files) - 10} more)"
        
        # Format the prompt
        prompt = self.template.format(
            max_length=self.config.max_length,
            files=files_list,
            stats=staged.summary,
            diff_content=diff_content
        )
        
        token_estimate = len(prompt) // self.CHARS_PER_TOKEN
        
        return BuiltCommitPrompt(
            content=prompt,
            token_estimate=token_estimate,
            staged_summary=staged.summary,
            style=self.config.style
        )


def generate_commit_prompt(
    staged: Optional[StagedChanges] = None,
    style: CommitStyle = CommitStyle.CONVENTIONAL,
    cwd: Optional[Path] = None
) -> BuiltCommitPrompt:
    """
    Convenience function to generate a commit message prompt.
    
    Args:
        staged: Staged changes (will be fetched if not provided)
        style: Commit message style
        cwd: Working directory
        
    Returns:
        BuiltCommitPrompt ready to send to AI
    """
    if staged is None:
        staged = get_staged_diff(cwd)
    
    config = CommitPromptConfig(style=style)
    builder = CommitPromptBuilder(config)
    return builder.build(staged)
