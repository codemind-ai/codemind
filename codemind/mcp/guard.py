"""CodeMind Guardian system for security and quality assurance."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict
import re

from ..rules.engine import RuleEngine, RuleMatch, RuleSeverity
from ..rules.presets import get_preset

class GuardType(Enum):
    SECURITY = "security"
    QUALITY = "quality"
    AI_SLOP = "ai_slop"

@dataclass
class GuardIssue:
    type: GuardType
    severity: RuleSeverity
    message: str
    file: Optional[str] = None
    line: Optional[int] = None
    code_snippet: Optional[str] = None
    suggestion: Optional[str] = None

@dataclass
class GuardReport:
    issues: List[GuardIssue] = field(default_factory=list)
    score: int = 100  # 0-100, where 100 is perfect
    
    @property
    def is_safe(self) -> bool:
        return not any(i.severity == RuleSeverity.CRITICAL for i in self.issues)
    
    @property
    def is_clean(self) -> bool:
        return self.score >= 80

class SecurityGuard:
    """Guards against security vulnerabilities."""
    
    def __init__(self):
        self.engine = RuleEngine()
        self.engine.add_rules(get_preset("security-strict"))
    
    def audit(self, code: str, filename: str = "unknown") -> List[GuardIssue]:
        matches = self.engine.evaluate_file(filename, code)
        issues = []
        for m in matches:
            issues.append(GuardIssue(
                type=GuardType.SECURITY,
                severity=m.rule.severity,
                message=m.rule.message or m.rule.description,
                file=filename,
                line=m.line,
                code_snippet=m.matched_text
            ))
        return issues

class QualityGuard:
    """Guards against poor code quality and 'AI Slop'."""
    
    SLOP_PATTERNS = [
        (r"// This function (adds|subtracts|multiplies|divides)", "Redundant comment explaining basic math", RuleSeverity.INFO),
        (r"//.*as an AI assistant", "AI-typical meta-comment", RuleSeverity.WARNING),
        (r"/\*\*.*This class represents a.*\*/", "Verbose, low-value Javadoc/Docstring", RuleSeverity.INFO),
        (r"\b(temp|data|result|val|var)\b", "Generic variable name", RuleSeverity.INFO),
        (r"//.*TODO:.*", "Unresolved TODO", RuleSeverity.INFO),
    ]
    
    def audit(self, code: str, filename: str = "unknown") -> List[GuardIssue]:
        issues = []
        lines = code.splitlines()
        
        for i, line in enumerate(lines, 1):
            for pattern, msg, severity in self.SLOP_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(GuardIssue(
                        type=GuardType.AI_SLOP,
                        severity=severity,
                        message=msg,
                        file=filename,
                        line=i,
                        code_snippet=line.strip()
                    ))
        
        # Simple SOLID/DRY heuristics could be added here
        # For now, we focus on the most visible "slop"
        return issues

class Guardian:
    """Main orchestrator for code guarding."""
    
    def __init__(self):
        self.security_guard = SecurityGuard()
        self.quality_guard = QualityGuard()
    
    def audit(self, code: str, filename: str = "unknown") -> GuardReport:
        issues = []
        issues.extend(self.security_guard.audit(code, filename))
        issues.extend(self.quality_guard.audit(code, filename))
        
        # Calculate score
        score = 100
        for issue in issues:
            if issue.severity == RuleSeverity.CRITICAL:
                score -= 20
            elif issue.severity == RuleSeverity.WARNING:
                score -= 10
            else:
                score -= 2
        
        return GuardReport(issues=issues, score=max(0, score))
