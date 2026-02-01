"""Tests for AI output parser module."""

import pytest
from codemind.validate.parser import (
    ReviewParser,
    ParsedReview,
    ReviewIssue,
    IssueSeverity,
    parse_review
)


class TestIssueSeverity:
    """Tests for IssueSeverity enum."""
    
    def test_severity_values(self):
        """Test severity enum values."""
        assert IssueSeverity.CRITICAL.value == "critical"
        assert IssueSeverity.WARNING.value == "warning"
        assert IssueSeverity.SUGGESTION.value == "suggestion"


class TestReviewIssue:
    """Tests for ReviewIssue dataclass."""
    
    def test_critical_issue(self):
        """Test critical issue creation."""
        issue = ReviewIssue(
            severity=IssueSeverity.CRITICAL,
            message="SQL injection vulnerability"
        )
        assert issue.is_critical is True
    
    def test_non_critical_issue(self):
        """Test non-critical issue."""
        issue = ReviewIssue(
            severity=IssueSeverity.WARNING,
            message="Missing error handling"
        )
        assert issue.is_critical is False
    
    def test_issue_with_file_and_line(self):
        """Test issue with file and line reference."""
        issue = ReviewIssue(
            severity=IssueSeverity.CRITICAL,
            message="Bug in database.py",
            file_path="database.py",
            line_number=42
        )
        assert issue.file_path == "database.py"
        assert issue.line_number == 42


class TestParsedReview:
    """Tests for ParsedReview dataclass."""
    
    def test_empty_review(self):
        """Test empty parsed review."""
        review = ParsedReview(raw_content="")
        assert review.total_issues == 0
        assert review.critical_count == 0
        assert review.warning_count == 0
        assert review.suggestion_count == 0
        assert review.is_clean is True
        assert review.has_critical is False
    
    def test_review_with_issues(self):
        """Test review with various issues."""
        issues = [
            ReviewIssue(severity=IssueSeverity.CRITICAL, message="Bug 1"),
            ReviewIssue(severity=IssueSeverity.CRITICAL, message="Bug 2"),
            ReviewIssue(severity=IssueSeverity.WARNING, message="Warning 1"),
            ReviewIssue(severity=IssueSeverity.SUGGESTION, message="Suggestion 1"),
        ]
        review = ParsedReview(raw_content="test", issues=issues)
        
        assert review.total_issues == 4
        assert review.critical_count == 2
        assert review.warning_count == 1
        assert review.suggestion_count == 1
        assert review.is_clean is False
        assert review.has_critical is True


class TestReviewParser:
    """Tests for ReviewParser class."""
    
    def test_parse_clean_response(self, sample_ai_response_clean):
        """Test parsing clean AI response."""
        parser = ReviewParser()
        result = parser.parse(sample_ai_response_clean)
        
        assert result.is_valid_format is True
        assert result.is_clean is True
        assert result.total_issues == 0
    
    def test_parse_response_with_issues(self, sample_ai_response_with_issues):
        """Test parsing response with issues."""
        parser = ReviewParser()
        result = parser.parse(sample_ai_response_with_issues)
        
        assert result.is_valid_format is True
        assert result.critical_count == 2
        assert result.warning_count == 2
        assert result.suggestion_count == 2
        assert result.total_issues == 6
    
    def test_parse_invalid_format(self, sample_ai_response_invalid_format):
        """Test parsing invalid format response."""
        parser = ReviewParser()
        result = parser.parse(sample_ai_response_invalid_format)
        
        assert result.is_valid_format is False
        assert len(result.format_errors) > 0
    
    def test_extract_line_numbers(self):
        """Test line number extraction from issues."""
        response = '''## 🚨 Critical
- Memory leak in `cache.py` line 42
- Buffer overflow at L15 in buffer.py

## ⚠️ Issues
None

## 💡 Suggestions
None
'''
        parser = ReviewParser()
        result = parser.parse(response)
        
        # Check that line numbers were extracted
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) == 2
        
        # First issue should have line 42
        assert critical_issues[0].line_number == 42
        # Second issue should have line 15
        assert critical_issues[1].line_number == 15
    
    def test_extract_file_paths(self):
        """Test file path extraction from issues."""
        response = '''## 🚨 Critical
- Bug in `database.py`
- Issue in file utils.py line 10

## ⚠️ Issues
None

## 💡 Suggestions
None
'''
        parser = ReviewParser()
        result = parser.parse(response)
        
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) == 2
        
        # Check file paths are extracted (may include or exclude backticks depending on parser)
        assert critical_issues[0].file_path is not None
        assert "database.py" in critical_issues[0].file_path
        assert critical_issues[1].file_path == "utils.py"
    
    def test_parse_multiline_issue(self):
        """Test parsing multi-line issue description."""
        response = '''## 🚨 Critical
- This is a critical issue that spans
  multiple lines and should be
  parsed as a single issue

## ⚠️ Issues
None

## 💡 Suggestions
None
'''
        parser = ReviewParser()
        result = parser.parse(response)
        
        assert result.critical_count == 1
        assert "multiple lines" in result.issues[0].message
    
    def test_parse_numbered_list(self):
        """Test parsing numbered list format."""
        response = '''## 🚨 Critical
1. First critical issue
2. Second critical issue

## ⚠️ Issues
None

## 💡 Suggestions
None
'''
        parser = ReviewParser()
        result = parser.parse(response)
        
        assert result.critical_count == 2
    
    def test_parse_various_bullet_styles(self):
        """Test parsing various bullet point styles."""
        response = '''## 🚨 Critical
- Dash style issue
* Asterisk style issue
• Bullet style issue

## ⚠️ Issues
None

## 💡 Suggestions
None
'''
        parser = ReviewParser()
        result = parser.parse(response)
        
        assert result.critical_count == 3


class TestConvenienceFunction:
    """Tests for parse_review convenience function."""
    
    def test_parse_review_function(self, sample_ai_response_clean):
        """Test parse_review convenience function."""
        result = parse_review(sample_ai_response_clean)
        
        assert isinstance(result, ParsedReview)
        assert result.is_clean is True
