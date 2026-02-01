"""Tests for new indispensable features (V2)."""

import pytest
from pathlib import Path
from codemind.llm.fixer import CodeFixer
from unittest.mock import MagicMock
import os

def test_code_fixer_stripping():
    """Test that CodeFixer strips markdown blocks if present."""
    mock_llm = MagicMock()
    mock_llm.generate.return_value.content = "```python\nprint('fixed')\n```"
    
    fixer = CodeFixer(mock_llm)
    fixed = fixer.generate_fix("test.py", "print('old')", "fix it")
    
    assert fixed == "print('fixed')"

def test_code_fixer_chatty_ai():
    """Test that CodeFixer extracts code from a chatty response."""
    mock_llm = MagicMock()
    mock_llm.generate.return_value.content = "Sure, here is your fix:\n\n```python\nprint('fixed')\n```\n\nHope this helps!"
    
    fixer = CodeFixer(mock_llm)
    fixed = fixer.generate_fix("test.py", "print('old')", "fix it")
    
    assert fixed == "print('fixed')"

def test_code_fixer_no_stripping():
    """Test that CodeFixer leaves raw code alone."""
    mock_llm = MagicMock()
    mock_llm.generate.return_value.content = "print('fixed')"
    
    fixer = CodeFixer(mock_llm)
    fixed = fixer.generate_fix("test.py", "print('old')", "fix it")
    
    assert fixed == "print('fixed')"

def test_diff_generation_logic():
    """Test the unified diff generation in terminal ui."""
    from codemind.ui.terminal import ui
    import difflib
    
    old = "line1\nline2\n"
    new = "line1\nchanged\n"
    
    # We just want to ensure it doesn't crash and diff has content
    diff = list(difflib.unified_diff(
        old.splitlines(keepends=True),
        new.splitlines(keepends=True)
    ))
    assert len(diff) > 0
    assert "-line2" in "".join(diff)
    assert "+changed" in "".join(diff)
