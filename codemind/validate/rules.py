"""Validation rules module.

Validates AI review output against configured rules.
"""

from dataclasses import dataclass, field
from typing import Optional

from .parser import ParsedReview, IssueSeverity


@dataclass
class ValidationResult:
    """Result of validation."""
    is_valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    
    def add_error(self, message: str) -> None:
        self.errors.append(message)
        self.is_valid = False
    
    def add_warning(self, message: str) -> None:
        self.warnings.append(message)


@dataclass
class ValidationConfig:
    """Configuration for validation."""
    max_comments: int = 5
    require_strict_format: bool = True
    fail_on_critical: bool = True
    fail_on_warning: bool = False
    allowed_files: Optional[list[str]] = None  # If set, issues must reference these files


class ReviewValidator:
    """Validates parsed review against rules."""
    
    def __init__(self, config: Optional[ValidationConfig] = None):
        self.config = config or ValidationConfig()
    
    def validate(self, review: ParsedReview) -> ValidationResult:
        """
        Validate a parsed review.
        
        Args:
            review: Parsed review to validate
        
        Returns:
            ValidationResult with any errors/warnings
        """
        result = ValidationResult()
        
        # Check format
        if self.config.require_strict_format and not review.is_valid_format:
            for error in review.format_errors:
                result.add_warning(f"Format issue: {error}")
        
        # Check comment count
        if review.total_issues > self.config.max_comments:
            result.add_warning(
                f"Review has {review.total_issues} issues, "
                f"exceeds max of {self.config.max_comments}"
            )
        
        # Check for critical issues
        if self.config.fail_on_critical and review.has_critical:
            result.add_error(
                f"Review found {review.critical_count} critical issue(s)"
            )
        
        # Check for warnings
        if self.config.fail_on_warning and review.warning_count > 0:
            result.add_error(
                f"Review found {review.warning_count} warning(s)"
            )
        
        # Check file references (if restricted)
        if self.config.allowed_files:
            for issue in review.issues:
                if issue.file_path and issue.file_path not in self.config.allowed_files:
                    result.add_warning(
                        f"Issue references file not in diff: {issue.file_path}"
                    )
        
        return result


def validate_review(
    review: ParsedReview,
    config: Optional[ValidationConfig] = None
) -> ValidationResult:
    """Convenience function to validate a review."""
    return ReviewValidator(config).validate(review)
