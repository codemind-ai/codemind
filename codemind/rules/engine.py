"""Rule engine module.

Provides pattern-matching and custom rule evaluation for code review.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Pattern


class RuleSeverity(Enum):
    """Rule severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    WARNING = "warning"

    INFO = "info"



@dataclass
class CustomRule:
    """A custom review rule with pattern matching."""
    name: str
    description: str
    severity: RuleSeverity
    pattern: Optional[str] = None  # Regex pattern to match
    message: str = ""  # Message to show when matched
    file_patterns: list[str] = field(default_factory=list)  # File patterns to apply to
    enabled: bool = True
    
    def __post_init__(self):
        if self.pattern:
            self._compiled_pattern = re.compile(self.pattern, re.MULTILINE)
        else:
            self._compiled_pattern = None
    
    def matches_file(self, filename: str) -> bool:
        """Check if rule applies to given filename."""
        if not self.file_patterns:
            return True  # Apply to all files
        
        for pattern in self.file_patterns:
            if re.match(pattern, filename):
                return True
        return False
    
    def find_matches(self, content: str) -> list[tuple[int, str]]:
        """
        Find all matches of the pattern in content.
        
        Returns:
            List of (line_number, matched_text) tuples
        """
        if not self._compiled_pattern:
            return []
        
        matches = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            if self._compiled_pattern.search(line):
                matches.append((i, line.strip()))
        
        return matches
    
    def to_prompt_instruction(self) -> str:
        """Convert rule to a prompt instruction."""
        msg = self.message or self.description
        return f"- [{self.severity.value.upper()}] {msg}"


@dataclass
class RuleMatch:
    """Represents a rule match in code."""
    rule: CustomRule
    file: str
    line: int
    matched_text: str
    
    @property
    def message(self) -> str:
        """Get the formatted message."""
        return f"{self.rule.message or self.rule.description} (line {self.line})"


class RuleEngine:
    """Engine for evaluating rules against code."""
    
    def __init__(self, rules: list[CustomRule] = None):
        self.rules = rules or []
    
    def add_rule(self, rule: CustomRule) -> None:
        """Add a rule to the engine."""
        self.rules.append(rule)
    
    def add_rules(self, rules: list[CustomRule]) -> None:
        """Add multiple rules."""
        self.rules.extend(rules)
    
    def clear_rules(self) -> None:
        """Clear all rules."""
        self.rules = []
    
    def get_enabled_rules(self) -> list[CustomRule]:
        """Get all enabled rules."""
        return [r for r in self.rules if r.enabled]
    
    def evaluate_file(self, filename: str, content: str) -> list[RuleMatch]:
        """
        Evaluate all rules against a file's content.
        
        Args:
            filename: Name of the file
            content: File content to check
            
        Returns:
            List of RuleMatch objects for violations found
        """
        matches = []
        
        for rule in self.get_enabled_rules():
            if not rule.matches_file(filename):
                continue
            
            rule_matches = rule.find_matches(content)
            for line, text in rule_matches:
                matches.append(RuleMatch(
                    rule=rule,
                    file=filename,
                    line=line,
                    matched_text=text,
                ))
        
        return matches
    
    def evaluate_diff(self, diff_content: str) -> list[RuleMatch]:
        """
        Evaluate rules against a diff.
        
        Only checks added lines (lines starting with +).
        
        Args:
            diff_content: Git diff content
            
        Returns:
            List of RuleMatch objects for violations in added code
        """
        matches = []
        current_file = None
        current_line = 0
        
        for line in diff_content.split('\n'):
            # Track current file
            if line.startswith('+++ b/'):
                current_file = line[6:]
                continue
            elif line.startswith('@@'):
                # Parse hunk header: @@ -old,count +new,count @@
                hunk_match = re.match(r'@@ -\d+(?:,\d+)? \+(\d+)', line)
                if hunk_match:
                    current_line = int(hunk_match.group(1)) - 1
                continue
            
            # Only check added lines
            if line.startswith('+') and not line.startswith('+++'):
                current_line += 1
                added_content = line[1:]  # Remove leading +
                
                if current_file:
                    for rule in self.get_enabled_rules():
                        if not rule.matches_file(current_file):
                            continue
                        
                        rule_matches = rule.find_matches(added_content)
                        for _, text in rule_matches:
                            matches.append(RuleMatch(
                                rule=rule,
                                file=current_file,
                                line=current_line,
                                matched_text=text,
                            ))
            elif not line.startswith('-'):
                current_line += 1
        
        return matches
    
    def generate_prompt_rules(self) -> list[str]:
        """Generate prompt instructions from all enabled rules."""
        return [r.to_prompt_instruction() for r in self.get_enabled_rules()]
    
    def get_summary(self, matches: list[RuleMatch]) -> dict:
        """Get a summary of rule matches."""
        critical = [m for m in matches if m.rule.severity == RuleSeverity.CRITICAL]
        warnings = [m for m in matches if m.rule.severity == RuleSeverity.WARNING]
        info = [m for m in matches if m.rule.severity == RuleSeverity.INFO]
        
        return {
            "total": len(matches),
            "critical": len(critical),
            "warnings": len(warnings),
            "info": len(info),
            "critical_matches": critical,
            "warning_matches": warnings,
            "info_matches": info,
        }


def load_rules_from_yaml(yaml_content: dict) -> list[CustomRule]:
    """
    Load custom rules from YAML config.
    
    Expected format:
    rules:
      custom:
        - name: no-console-log
          pattern: "console\\.log"
          message: "Remove console.log before committing"
          severity: warning
          file_patterns:
            - ".*\\.js$"
            - ".*\\.ts$"
    """
    rules = []
    custom_rules = yaml_content.get("rules", {}).get("custom", [])
    
    for rule_dict in custom_rules:
        severity_str = rule_dict.get("severity", "info").lower()
        severity = {
            "critical": RuleSeverity.CRITICAL,
            "warning": RuleSeverity.WARNING,
            "info": RuleSeverity.INFO,
        }.get(severity_str, RuleSeverity.INFO)
        
        rules.append(CustomRule(
            name=rule_dict.get("name", "custom-rule"),
            description=rule_dict.get("description", ""),
            pattern=rule_dict.get("pattern"),
            message=rule_dict.get("message", ""),
            severity=severity,
            file_patterns=rule_dict.get("file_patterns", []),
            enabled=rule_dict.get("enabled", True),
        ))
    
    return rules
