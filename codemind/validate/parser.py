"""AI output parser module.

Parses and validates AI review responses.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class IssueSeverity(Enum):
    """Severity of an issue."""
    CRITICAL = "critical"
    WARNING = "warning"
    SUGGESTION = "suggestion"


@dataclass
class ReviewIssue:
    """A single issue from the review."""
    severity: IssueSeverity
    message: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    
    @property
    def is_critical(self) -> bool:
        return self.severity == IssueSeverity.CRITICAL


@dataclass
class ParsedReview:
    """Parsed AI review output."""
    raw_content: str
    issues: list[ReviewIssue] = field(default_factory=list)
    is_valid_format: bool = True
    format_errors: list[str] = field(default_factory=list)
    
    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == IssueSeverity.CRITICAL)
    
    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == IssueSeverity.WARNING)
    
    @property
    def suggestion_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == IssueSeverity.SUGGESTION)
    
    @property
    def total_issues(self) -> int:
        return len(self.issues)
    
    @property
    def has_critical(self) -> bool:
        return self.critical_count > 0
    
    @property
    def is_clean(self) -> bool:
        """No issues found or only "None" in all sections."""
        return self.total_issues == 0


class ReviewParser:
    """Parses AI review output into structured format."""
    
    # Section patterns (supports with and without emojis)
    CRITICAL_PATTERN = re.compile(
        r'##\s*(?:🚨\s*)?Critical\s*\n(.*?)(?=##|$)',
        re.IGNORECASE | re.DOTALL
    )
    ISSUES_PATTERN = re.compile(
        r'##\s*(?:⚠️?\s*)?Issues?\s*\n(.*?)(?=##|$)',
        re.IGNORECASE | re.DOTALL
    )
    SUGGESTIONS_PATTERN = re.compile(
        r'##\s*(?:💡\s*)?Suggestions?\s*\n(.*?)(?=##|$)',
        re.IGNORECASE | re.DOTALL
    )
    
    # Line reference pattern (e.g., "line 42", "L42", "lines 10-15")
    LINE_REF_PATTERN = re.compile(
        r'(?:line|L)s?\s*(\d+)(?:\s*-\s*(\d+))?',
        re.IGNORECASE
    )
    
    # File reference pattern
    FILE_REF_PATTERN = re.compile(
        r'`([^`]+\.\w+)`|(?:in|file)\s+(\S+\.\w+)',
        re.IGNORECASE
    )
    
    def parse(self, content: str) -> ParsedReview:
        """
        Parse AI review output.
        
        Args:
            content: Raw AI output
        
        Returns:
            ParsedReview with extracted issues
        """
        result = ParsedReview(raw_content=content)
        
        # Check for expected format
        has_critical = bool(self.CRITICAL_PATTERN.search(content))
        has_issues = bool(self.ISSUES_PATTERN.search(content))
        has_suggestions = bool(self.SUGGESTIONS_PATTERN.search(content))
        
        if not (has_critical or has_issues or has_suggestions):
            result.is_valid_format = False
            result.format_errors.append(
                "Missing expected sections (Critical/Issues/Suggestions)"
            )
        
        # Parse each section
        result.issues.extend(self._parse_section(
            content, self.CRITICAL_PATTERN, IssueSeverity.CRITICAL
        ))
        result.issues.extend(self._parse_section(
            content, self.ISSUES_PATTERN, IssueSeverity.WARNING
        ))
        result.issues.extend(self._parse_section(
            content, self.SUGGESTIONS_PATTERN, IssueSeverity.SUGGESTION
        ))
        
        return result
    
    def _parse_section(
        self,
        content: str,
        pattern: re.Pattern,
        severity: IssueSeverity
    ) -> list[ReviewIssue]:
        """Parse a single section of the review."""
        issues = []
        
        match = pattern.search(content)
        if not match:
            return issues
        
        section_content = match.group(1).strip()
        
        # Check for "None" or empty
        if not section_content or section_content.lower() in ["none", "n/a", "-"]:
            return issues
        
        # Parse bullet points
        lines = section_content.split('\n')
        current_issue = []
        
        for line in lines:
            line = line.strip()
            
            # New bullet point
            if line.startswith(('-', '*', '•', '·')) or re.match(r'^\d+\.', line):
                if current_issue:
                    issues.append(self._parse_issue_line(
                        ' '.join(current_issue), severity
                    ))
                current_issue = [line.lstrip('-*•·0123456789. ')]
            elif line and current_issue:
                # Continuation of previous bullet
                current_issue.append(line)
        
        # Don't forget the last issue
        if current_issue:
            issues.append(self._parse_issue_line(
                ' '.join(current_issue), severity
            ))
        
        return issues
    
    def _parse_issue_line(self, text: str, severity: IssueSeverity) -> ReviewIssue:
        """Parse a single issue line."""
        issue = ReviewIssue(severity=severity, message=text)
        
        # Try to extract line number
        line_match = self.LINE_REF_PATTERN.search(text)
        if line_match:
            issue.line_number = int(line_match.group(1))
        
        # Try to extract file path
        file_match = self.FILE_REF_PATTERN.search(text)
        if file_match:
            issue.file_path = file_match.group(1) or file_match.group(2)
        
        return issue


def parse_review(content: str) -> ParsedReview:
    """Convenience function to parse review output."""
    return ReviewParser().parse(content)
