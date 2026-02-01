"""Commit module initialization."""

from .generator import (
    CommitStyle,
    CommitPromptBuilder,
    generate_commit_prompt,
    get_staged_diff,
)

__all__ = [
    "CommitStyle",
    "CommitPromptBuilder", 
    "generate_commit_prompt",
    "get_staged_diff",
]
