"""Tests for git utils module."""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from codemind.git.utils import (
    run_git_command,
    GitError,
    GitTimeoutError,
    GitNotFoundError,
    DEFAULT_GIT_TIMEOUT,
)


class TestRunGitCommand:
    """Tests for run_git_command function."""
    
    def test_successful_command(self):
        """Test successful git command execution."""
        # This will work if git is installed
        output, code = run_git_command("--version")
        assert code == 0
        assert "git version" in output.lower()
    
    def test_returns_output_and_code(self):
        """Test that function returns tuple of output and return code."""
        output, code = run_git_command("status", "--porcelain", cwd=Path.cwd())
        assert isinstance(output, str)
        assert isinstance(code, int)
    
    @patch("codemind.git.utils.subprocess.run")
    def test_timeout_raises_exception(self, mock_run):
        """Test that timeout raises GitTimeoutError."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="git", timeout=30)
        
        with pytest.raises(GitTimeoutError) as exc_info:
            run_git_command("status")
        
        assert "timed out" in str(exc_info.value).lower()
    
    @patch("codemind.git.utils.subprocess.run")
    def test_git_not_found_raises_exception(self, mock_run):
        """Test that missing git raises GitNotFoundError."""
        mock_run.side_effect = FileNotFoundError()
        
        with pytest.raises(GitNotFoundError) as exc_info:
            run_git_command("status")
        
        assert "not installed" in str(exc_info.value).lower()
    
    def test_default_timeout_value(self):
        """Test that default timeout is reasonable."""
        assert DEFAULT_GIT_TIMEOUT == 30
    
    @patch("codemind.git.utils.subprocess.run")
    def test_custom_timeout(self, mock_run):
        """Test that custom timeout is passed to subprocess."""
        mock_result = MagicMock()
        mock_result.stdout = "output"
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        run_git_command("status", timeout=60)
        
        _, kwargs = mock_run.call_args
        assert kwargs["timeout"] == 60
    
    @patch("codemind.git.utils.subprocess.run")
    def test_custom_cwd(self, mock_run):
        """Test that custom cwd is passed to subprocess."""
        mock_result = MagicMock()
        mock_result.stdout = "output"
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        custom_path = Path("/some/path")
        run_git_command("status", cwd=custom_path)
        
        _, kwargs = mock_run.call_args
        assert kwargs["cwd"] == custom_path


class TestExceptions:
    """Tests for exception classes."""
    
    def test_git_error_is_exception(self):
        """Test GitError is an Exception."""
        assert issubclass(GitError, Exception)
    
    def test_timeout_error_inherits_git_error(self):
        """Test GitTimeoutError inherits from GitError."""
        assert issubclass(GitTimeoutError, GitError)
    
    def test_not_found_error_inherits_git_error(self):
        """Test GitNotFoundError inherits from GitError."""
        assert issubclass(GitNotFoundError, GitError)
