"""Tests for prompt builder module."""

import pytest
from pathlib import Path
from codemind.prompt.builder import (
    PromptBuilder,
    PromptConfig,
    BuiltPrompt,
    build_prompt
)
from codemind.git.diff import DiffResult, FileDiff
from codemind.git.context import GitContext


class TestPromptConfig:
    """Tests for PromptConfig dataclass."""
    
    def test_default_values(self):
        """Test default configuration values."""
        config = PromptConfig()
        assert config.max_comments == 5
        assert config.strict_format is True
        assert config.review_only_diff is True
        assert config.allow_feature_suggestions is False
        assert config.extra_rules == []
        assert config.file_patterns_to_focus == []
    
    def test_custom_values(self):
        """Test custom configuration values."""
        config = PromptConfig(
            max_comments=10,
            strict_format=False,
            extra_rules=["Rule 1", "Rule 2"]
        )
        assert config.max_comments == 10
        assert config.strict_format is False
        assert len(config.extra_rules) == 2


class TestBuiltPrompt:
    """Tests for BuiltPrompt dataclass."""
    
    def test_default_values(self):
        """Test default built prompt values."""
        prompt = BuiltPrompt(
            content="Test prompt",
            token_estimate=100,
            file_count=2,
            line_count=50
        )
        assert prompt.content == "Test prompt"
        assert prompt.truncated is False
        assert prompt.warning is None
    
    def test_truncated_prompt(self):
        """Test truncated prompt."""
        prompt = BuiltPrompt(
            content="Truncated prompt",
            token_estimate=100,
            file_count=2,
            line_count=50,
            truncated=True,
            warning="Diff was truncated"
        )
        assert prompt.truncated is True
        assert prompt.warning is not None


class TestPromptBuilder:
    """Tests for PromptBuilder class."""
    
    @pytest.fixture
    def simple_diff_result(self):
        """Create a simple diff result for testing."""
        return DiffResult(
            files=[FileDiff(path="test.py", additions=10, deletions=5)],
            total_files=1,
            total_additions=10,
            total_deletions=5,
            raw_diff="diff --git a/test.py b/test.py\n+new line"
        )
    
    @pytest.fixture
    def git_context(self):
        """Create a git context for testing."""
        return GitContext(
            repo_root=Path.cwd(),
            current_branch="feature/test",
            upstream_branch="origin/main",
            is_dirty=False,
            has_staged=False
        )
    
    def test_build_basic_prompt(self, simple_diff_result, git_context):
        """Test building a basic prompt."""
        builder = PromptBuilder()
        result = builder.build(simple_diff_result, git_context)
        
        assert isinstance(result, BuiltPrompt)
        assert result.file_count == 1
        assert result.line_count == 15
        assert result.truncated is False
        assert len(result.content) > 0
    
    def test_prompt_contains_diff(self, simple_diff_result, git_context):
        """Test that prompt contains the diff content."""
        builder = PromptBuilder()
        result = builder.build(simple_diff_result, git_context)
        
        assert "test.py" in result.content or "diff" in result.content.lower()
    
    def test_prompt_contains_branch(self, simple_diff_result, git_context):
        """Test that prompt contains branch info."""
        builder = PromptBuilder()
        result = builder.build(simple_diff_result, git_context)
        
        assert "feature/test" in result.content
    
    def test_prompt_with_extra_rules(self, simple_diff_result, git_context):
        """Test prompt with extra rules."""
        config = PromptConfig(
            extra_rules=["Focus on security", "Check for SQL injection"]
        )
        builder = PromptBuilder(config)
        result = builder.build(simple_diff_result, git_context)
        
        assert "Focus on security" in result.content
        assert "SQL injection" in result.content
    
    def test_token_estimate(self, simple_diff_result, git_context):
        """Test token estimation."""
        builder = PromptBuilder()
        result = builder.build(simple_diff_result, git_context)
        
        # Token estimate should be roughly content_length / 4
        expected_estimate = len(result.content) // 4
        assert abs(result.token_estimate - expected_estimate) <= 1
    
    def test_truncation_for_large_diff(self, git_context):
        """Test truncation for large diffs."""
        # Create a large diff
        large_diff = "diff --git a/large.py b/large.py\n"
        large_diff += "+line\n" * 20000  # Very long diff
        
        diff_result = DiffResult(
            files=[FileDiff(path="large.py", additions=20000, deletions=0)],
            total_files=1,
            total_additions=20000,
            total_deletions=0,
            raw_diff=large_diff
        )
        
        builder = PromptBuilder()
        result = builder.build(diff_result, git_context)
        
        assert result.truncated is True
        assert result.warning is not None
        assert "truncated" in result.warning.lower()
    
    def test_build_without_context(self, simple_diff_result):
        """Test building prompt without git context."""
        builder = PromptBuilder()
        result = builder.build(simple_diff_result, context=None)
        
        assert isinstance(result, BuiltPrompt)
        assert "unknown" in result.content  # Default branch name


class TestConvenienceFunction:
    """Tests for build_prompt convenience function."""
    
    def test_build_prompt_function(self):
        """Test build_prompt convenience function."""
        diff_result = DiffResult(
            files=[FileDiff(path="test.py", additions=5, deletions=2)],
            total_files=1,
            total_additions=5,
            total_deletions=2,
            raw_diff="diff content"
        )
        
        result = build_prompt(diff_result)
        
        assert isinstance(result, BuiltPrompt)
        assert result.file_count == 1
