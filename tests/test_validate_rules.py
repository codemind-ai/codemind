"""Tests for validation rules module."""

import pytest
from codemind.validate.rules import (
    ValidationResult,
    ValidationConfig,
    ReviewValidator,
    validate_review
)
from codemind.validate.parser import (
    ParsedReview,
    ReviewIssue,
    IssueSeverity
)


class TestValidationResult:
    """Tests for ValidationResult dataclass."""
    
    def test_default_state(self):
        """Test default validation result."""
        result = ValidationResult()
        assert result.is_valid is True
        assert result.errors == []
        assert result.warnings == []
    
    def test_add_error(self):
        """Test adding an error."""
        result = ValidationResult()
        result.add_error("Test error")
        
        assert result.is_valid is False
        assert len(result.errors) == 1
        assert "Test error" in result.errors
    
    def test_add_warning(self):
        """Test adding a warning."""
        result = ValidationResult()
        result.add_warning("Test warning")
        
        # Warnings don't affect validity
        assert result.is_valid is True
        assert len(result.warnings) == 1
        assert "Test warning" in result.warnings
    
    def test_multiple_errors_and_warnings(self):
        """Test multiple errors and warnings."""
        result = ValidationResult()
        result.add_error("Error 1")
        result.add_error("Error 2")
        result.add_warning("Warning 1")
        
        assert result.is_valid is False
        assert len(result.errors) == 2
        assert len(result.warnings) == 1


class TestValidationConfig:
    """Tests for ValidationConfig dataclass."""
    
    def test_default_config(self):
        """Test default configuration."""
        config = ValidationConfig()
        assert config.max_comments == 5
        assert config.require_strict_format is True
        assert config.fail_on_critical is True
        assert config.fail_on_warning is False
        assert config.allowed_files is None
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = ValidationConfig(
            max_comments=10,
            fail_on_warning=True,
            allowed_files=["main.py", "utils.py"]
        )
        assert config.max_comments == 10
        assert config.fail_on_warning is True
        assert len(config.allowed_files) == 2


class TestReviewValidator:
    """Tests for ReviewValidator class."""
    
    def test_validate_clean_review(self, sample_ai_response_clean):
        """Test validating a clean review."""
        from codemind.validate.parser import parse_review
        
        parsed = parse_review(sample_ai_response_clean)
        validator = ReviewValidator()
        result = validator.validate(parsed)
        
        assert result.is_valid is True
        assert len(result.errors) == 0
    
    def test_validate_review_with_critical_issues(self):
        """Test validating review with critical issues."""
        issues = [
            ReviewIssue(severity=IssueSeverity.CRITICAL, message="Bug 1"),
        ]
        parsed = ParsedReview(raw_content="test", issues=issues)
        
        validator = ReviewValidator()
        result = validator.validate(parsed)
        
        assert result.is_valid is False
        assert "critical" in result.errors[0].lower()
    
    def test_validate_with_fail_on_critical_disabled(self):
        """Test validation with fail_on_critical disabled."""
        issues = [
            ReviewIssue(severity=IssueSeverity.CRITICAL, message="Bug 1"),
        ]
        parsed = ParsedReview(raw_content="test", issues=issues)
        
        config = ValidationConfig(fail_on_critical=False)
        validator = ReviewValidator(config)
        result = validator.validate(parsed)
        
        assert result.is_valid is True
    
    def test_validate_with_fail_on_warning(self):
        """Test validation with fail_on_warning enabled."""
        issues = [
            ReviewIssue(severity=IssueSeverity.WARNING, message="Warning 1"),
        ]
        parsed = ParsedReview(raw_content="test", issues=issues)
        
        config = ValidationConfig(fail_on_warning=True)
        validator = ReviewValidator(config)
        result = validator.validate(parsed)
        
        assert result.is_valid is False
        assert "warning" in result.errors[0].lower()
    
    def test_validate_exceeds_max_comments(self):
        """Test validation when exceeding max comments."""
        issues = [
            ReviewIssue(severity=IssueSeverity.SUGGESTION, message=f"Suggestion {i}")
            for i in range(10)
        ]
        parsed = ParsedReview(raw_content="test", issues=issues)
        
        config = ValidationConfig(max_comments=5)
        validator = ReviewValidator(config)
        result = validator.validate(parsed)
        
        # Should only add warning, not error
        assert result.is_valid is True
        assert any("exceeds" in w.lower() for w in result.warnings)
    
    def test_validate_invalid_format(self):
        """Test validation with invalid format."""
        parsed = ParsedReview(
            raw_content="test",
            is_valid_format=False,
            format_errors=["Missing sections"]
        )
        
        validator = ReviewValidator()
        result = validator.validate(parsed)
        
        # Format issues are warnings, not errors
        assert len(result.warnings) > 0
        assert "format" in result.warnings[0].lower()
    
    def test_validate_file_not_in_allowed_list(self):
        """Test validation when file not in allowed list."""
        issues = [
            ReviewIssue(
                severity=IssueSeverity.WARNING,
                message="Issue in forbidden.py",
                file_path="forbidden.py"
            ),
        ]
        parsed = ParsedReview(raw_content="test", issues=issues)
        
        config = ValidationConfig(
            fail_on_warning=False,
            allowed_files=["main.py", "utils.py"]
        )
        validator = ReviewValidator(config)
        result = validator.validate(parsed)
        
        assert any("not in diff" in w.lower() for w in result.warnings)


class TestConvenienceFunction:
    """Tests for validate_review convenience function."""
    
    def test_validate_review_function(self):
        """Test validate_review convenience function."""
        parsed = ParsedReview(raw_content="test", issues=[])
        result = validate_review(parsed)
        
        assert isinstance(result, ValidationResult)
        assert result.is_valid is True
