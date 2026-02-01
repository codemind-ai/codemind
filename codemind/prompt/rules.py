"""Review rules configuration module.

Defines configurable rules for code review prompts.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Issue severity levels."""
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class RuleCategory(Enum):
    """Categories of review rules."""
    SECURITY = "security"
    BUGS = "bugs"
    PERFORMANCE = "performance"
    STYLE = "style"
    MAINTAINABILITY = "maintainability"


@dataclass
class ReviewRule:
    """A single review rule."""
    name: str
    description: str
    category: RuleCategory
    severity: Severity
    enabled: bool = True
    
    def to_prompt_line(self) -> str:
        """Convert rule to a prompt instruction line."""
        return f"- Check for {self.description} [{self.category.value}]"


@dataclass
class RuleSet:
    """A collection of review rules."""
    rules: list[ReviewRule] = field(default_factory=list)
    fail_on: list[Severity] = field(default_factory=lambda: [Severity.CRITICAL])
    
    def get_enabled_rules(self) -> list[ReviewRule]:
        """Get all enabled rules."""
        return [r for r in self.rules if r.enabled]
    
    def get_rules_by_category(self, category: RuleCategory) -> list[ReviewRule]:
        """Get rules filtered by category."""
        return [r for r in self.rules if r.category == category and r.enabled]
    
    def to_prompt_lines(self) -> list[str]:
        """Convert all enabled rules to prompt instruction lines."""
        return [r.to_prompt_line() for r in self.get_enabled_rules()]


# Default rules
DEFAULT_RULES = RuleSet(
    rules=[
        ReviewRule(
            name="sql_injection",
            description="SQL injection vulnerabilities",
            category=RuleCategory.SECURITY,
            severity=Severity.CRITICAL
        ),
        ReviewRule(
            name="xss",
            description="cross-site scripting (XSS) vulnerabilities",
            category=RuleCategory.SECURITY,
            severity=Severity.CRITICAL
        ),
        ReviewRule(
            name="secrets",
            description="hardcoded secrets, API keys, or passwords",
            category=RuleCategory.SECURITY,
            severity=Severity.CRITICAL
        ),
        ReviewRule(
            name="null_pointer",
            description="potential null pointer dereferences",
            category=RuleCategory.BUGS,
            severity=Severity.CRITICAL
        ),
        ReviewRule(
            name="race_condition",
            description="race conditions or thread safety issues",
            category=RuleCategory.BUGS,
            severity=Severity.CRITICAL
        ),
        ReviewRule(
            name="resource_leak",
            description="resource leaks (file handles, connections)",
            category=RuleCategory.BUGS,
            severity=Severity.WARNING
        ),
        ReviewRule(
            name="error_handling",
            description="missing or improper error handling",
            category=RuleCategory.BUGS,
            severity=Severity.WARNING
        ),
        ReviewRule(
            name="complexity",
            description="overly complex code that should be simplified",
            category=RuleCategory.MAINTAINABILITY,
            severity=Severity.INFO
        ),
        ReviewRule(
            name="naming",
            description="unclear or misleading variable/function names",
            category=RuleCategory.STYLE,
            severity=Severity.INFO
        ),
    ],
    fail_on=[Severity.CRITICAL]
)


def get_default_rules() -> RuleSet:
    """Get the default rule set."""
    return DEFAULT_RULES
