"""Tests for commit message generator."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from codemind.commit.generator import (
    CommitStyle,
    StagedChanges,
    CommitPromptConfig,
    CommitPromptBuilder,
    get_staged_diff,
    generate_commit_prompt,
)


class TestCommitStyle:
    """Test CommitStyle enum."""
    
    def test_conventional_style(self):
        assert CommitStyle.CONVENTIONAL.value == "conventional"
    
    def test_simple_style(self):
        assert CommitStyle.SIMPLE.value == "simple"
    
    def test_descriptive_style(self):
        assert CommitStyle.DESCRIPTIVE.value == "descriptive"


class TestStagedChanges:
    """Test StagedChanges dataclass."""
    
    def test_total_lines(self):
        staged = StagedChanges(
            diff="some diff",
            files=["file1.py", "file2.py"],
            additions=10,
            deletions=5,
        )
        assert staged.total_lines == 15
    
    def test_summary(self):
        staged = StagedChanges(
            diff="some diff",
            files=["file1.py", "file2.py"],
            additions=10,
            deletions=5,
        )
        assert staged.summary == "2 files, +10/-5"
    
    def test_empty_staged(self):
        staged = StagedChanges(
            diff="",
            files=[],
            additions=0,
            deletions=0,
            is_empty=True
        )
        assert staged.is_empty
        assert staged.total_lines == 0


class TestCommitPromptConfig:
    """Test CommitPromptConfig dataclass."""
    
    def test_default_values(self):
        config = CommitPromptConfig()
        assert config.style == CommitStyle.CONVENTIONAL
        assert config.max_length == 72
        assert config.include_body is True
    
    def test_custom_values(self):
        config = CommitPromptConfig(
            style=CommitStyle.SIMPLE,
            max_length=50,
            include_body=False
        )
        assert config.style == CommitStyle.SIMPLE
        assert config.max_length == 50


class TestCommitPromptBuilder:
    """Test CommitPromptBuilder class."""
    
    @pytest.fixture
    def sample_staged(self):
        return StagedChanges(
            diff="""diff --git a/main.py b/main.py
--- a/main.py
+++ b/main.py
@@ -1,3 +1,4 @@
 import os
+import sys
 
 def main():
     pass""",
            files=["main.py"],
            additions=1,
            deletions=0,
        )
    
    def test_build_conventional_prompt(self, sample_staged):
        config = CommitPromptConfig(style=CommitStyle.CONVENTIONAL)
        builder = CommitPromptBuilder(config)
        result = builder.build(sample_staged)
        
        assert result.content
        assert "Conventional Commits" in result.content
        assert "feat:" in result.content or "fix:" in result.content
        assert "main.py" in result.content
        assert result.style == CommitStyle.CONVENTIONAL
    
    def test_build_simple_prompt(self, sample_staged):
        config = CommitPromptConfig(style=CommitStyle.SIMPLE)
        builder = CommitPromptBuilder(config)
        result = builder.build(sample_staged)
        
        assert result.content
        assert "simple" in result.content.lower() or "clear" in result.content.lower()
        assert result.style == CommitStyle.SIMPLE
    
    def test_build_descriptive_prompt(self, sample_staged):
        config = CommitPromptConfig(style=CommitStyle.DESCRIPTIVE)
        builder = CommitPromptBuilder(config)
        result = builder.build(sample_staged)
        
        assert result.content
        assert "detailed" in result.content.lower() or "descriptive" in result.content.lower()
        assert result.style == CommitStyle.DESCRIPTIVE
    
    def test_token_estimate(self, sample_staged):
        builder = CommitPromptBuilder()
        result = builder.build(sample_staged)
        
        # Token estimate should be roughly content length / 4
        expected = len(result.content) // 4
        assert result.token_estimate == expected
    
    def test_truncation_for_large_diff(self):
        large_diff = "+" * 50000
        staged = StagedChanges(
            diff=large_diff,
            files=["large_file.py"],
            additions=50000,
            deletions=0,
        )
        
        builder = CommitPromptBuilder()
        result = builder.build(staged)
        
        # Should contain truncation notice
        assert "truncated" in result.content.lower()


class TestGetStagedDiff:
    """Test get_staged_diff function."""
    
    @patch('codemind.commit.generator.run_git_command')
    def test_empty_staged(self, mock_run_git):
        mock_run_git.return_value = ("", 0)
        
        result = get_staged_diff()
        
        assert result.is_empty
        assert result.files == []
    
    @patch('codemind.commit.generator.run_git_command')
    def test_with_staged_changes(self, mock_run_git):
        def side_effect(*args, **kwargs):
            if args[0] == "diff" and args[1] == "--cached" and len(args) == 2:
                return ("diff --git a/test.py...", 0)
            elif "--name-only" in args:
                return ("test.py\nutils.py", 0)
            elif "--stat" in args:
                return ("2 files changed, 10 insertions(+), 5 deletions(-)", 0)
            return ("", 0)
        
        mock_run_git.side_effect = side_effect
        
        result = get_staged_diff()
        
        assert not result.is_empty
        assert "test.py" in result.files


class TestGenerateCommitPrompt:
    """Test generate_commit_prompt convenience function."""
    
    def test_with_provided_staged(self):
        staged = StagedChanges(
            diff="some diff content",
            files=["file.py"],
            additions=5,
            deletions=2,
        )
        
        result = generate_commit_prompt(staged, style=CommitStyle.SIMPLE)
        
        assert result.content
        assert result.style == CommitStyle.SIMPLE
        assert result.staged_summary == "1 files, +5/-2"
