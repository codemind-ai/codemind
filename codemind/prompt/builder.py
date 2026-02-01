"""Prompt builder module.

Builds structured, enhanced prompts for AI code review.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..git.diff import DiffResult
from ..git.context import GitContext


# Default template path
TEMPLATE_DIR = Path(__file__).parent / "templates"
DEFAULT_TEMPLATE = TEMPLATE_DIR / "review.txt"


@dataclass
class PromptConfig:
    """Configuration for prompt generation."""
    max_comments: int = 5
    strict_format: bool = True
    review_only_diff: bool = True
    allow_feature_suggestions: bool = False
    template_path: Optional[Path] = None
    
    # Additional context (optional)
    extra_rules: list[str] = field(default_factory=list)
    file_patterns_to_focus: list[str] = field(default_factory=list)


@dataclass
class BuiltPrompt:
    """Result of prompt building."""
    content: str
    token_estimate: int  # Rough estimate
    file_count: int
    line_count: int
    truncated: bool = False
    warning: Optional[str] = None


class PromptBuilder:
    """Builds review prompts from git diffs."""
    
    # Rough estimate: 4 chars per token
    CHARS_PER_TOKEN = 4
    
    # Max diff size before truncation (in chars)
    MAX_DIFF_CHARS = 50000  # ~12.5k tokens
    
    def __init__(self, config: Optional[PromptConfig] = None):
        self.config = config or PromptConfig()
        self.template = self._load_template()
    
    def _load_template(self) -> str:
        """Load the prompt template."""
        template_path = self.config.template_path or DEFAULT_TEMPLATE
        
        if not template_path.exists():
            raise FileNotFoundError(f"Template not found: {template_path}")
        
        return template_path.read_text(encoding="utf-8")
    
    def build(
        self,
        diff_result: DiffResult,
        context: Optional[GitContext] = None
    ) -> BuiltPrompt:
        """
        Build a review prompt from a diff result.
        
        Args:
            diff_result: Parsed git diff
            context: Git context (optional)
        
        Returns:
            BuiltPrompt with the generated prompt content
        """
        # Prepare diff content
        diff_content = diff_result.raw_diff
        truncated = False
        warning = None
        
        # Truncate if too large
        if len(diff_content) > self.MAX_DIFF_CHARS:
            diff_content = self._truncate_diff(diff_content)
            truncated = True
            warning = (
                f"⚠️ Diff truncated from {len(diff_result.raw_diff)} to "
                f"{len(diff_content)} chars due to size limits."
            )
        
        # Build prompt from template
        prompt_content = self.template.format(
            max_comments=self.config.max_comments,
            branch_name=context.current_branch if context else "unknown",
            file_count=diff_result.total_files,
            additions=diff_result.total_additions,
            deletions=diff_result.total_deletions,
            diff_content=diff_content
        )
        
        # Add extra rules if configured
        if self.config.extra_rules:
            extra_section = "\n\nADDITIONAL RULES:\n" + "\n".join(
                f"- {rule}" for rule in self.config.extra_rules
            )
            # Insert before the diff section
            prompt_content = prompt_content.replace(
                "\n---\n",
                f"{extra_section}\n\n---\n",
                1
            )
        
        # Calculate token estimate
        token_estimate = len(prompt_content) // self.CHARS_PER_TOKEN
        
        return BuiltPrompt(
            content=prompt_content,
            token_estimate=token_estimate,
            file_count=diff_result.total_files,
            line_count=diff_result.total_lines,
            truncated=truncated,
            warning=warning
        )
    
    def _truncate_diff(self, diff_content: str) -> str:
        """
        Intelligently truncate diff content.
        
        Strategy:
        1. Keep file headers
        2. Prioritize smaller files
        3. Cut large hunks
        """
        lines = diff_content.split('\n')
        result_lines = []
        current_size = 0
        
        for line in lines:
            line_size = len(line) + 1  # +1 for newline
            
            if current_size + line_size > self.MAX_DIFF_CHARS:
                result_lines.append("\n... [diff truncated due to size] ...")
                break
            
            result_lines.append(line)
            current_size += line_size
        
        return '\n'.join(result_lines)


def build_prompt(
    diff_result: DiffResult,
    context: Optional[GitContext] = None,
    config: Optional[PromptConfig] = None
) -> BuiltPrompt:
    """
    Convenience function to build a review prompt.
    
    Args:
        diff_result: Parsed git diff
        context: Git context (optional)
        config: Prompt configuration (optional)
    
    Returns:
        BuiltPrompt with the generated prompt content
    """
    builder = PromptBuilder(config)
    return builder.build(diff_result, context)
