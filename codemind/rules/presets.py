"""Rule presets module.

Provides pre-built rule sets for common use cases.
"""

from .engine import CustomRule, RuleSeverity


# Security-focused ruleset
SECURITY_STRICT = [
    CustomRule(
        name="hardcoded-password",
        description="Hardcoded password detection",
        pattern=r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']',
        message="Hardcoded password detected - use environment variables",
        severity=RuleSeverity.CRITICAL,
    ),
    CustomRule(
        name="hardcoded-api-key",
        description="Hardcoded API key detection", 
        pattern=r'(?i)(api[_-]?key|apikey|secret[_-]?key)\s*=\s*["\'][^"\']+["\']',
        message="Hardcoded API key detected - use environment variables or secrets manager",
        severity=RuleSeverity.CRITICAL,
    ),
    CustomRule(
        name="sql-injection",
        description="Potential SQL injection",
        pattern=r'(?i)execute\s*\([^)]*\+|\%s[^)]*\)|f["\'].*SELECT.*{',
        message="Potential SQL injection - use parameterized queries",
        severity=RuleSeverity.CRITICAL,
    ),
    CustomRule(
        name="eval-usage",
        description="Dangerous eval() usage",
        pattern=r'\beval\s*\(',
        message="eval() is dangerous - avoid using it with user input",
        severity=RuleSeverity.CRITICAL,
        file_patterns=[r'.*\.py$', r'.*\.js$', r'.*\.ts$'],
    ),
    CustomRule(
        name="exec-usage",
        description="Dangerous exec() usage",
        pattern=r'\bexec\s*\(',
        message="exec() is dangerous - avoid using it with user input", 
        severity=RuleSeverity.CRITICAL,
        file_patterns=[r'.*\.py$'],
    ),
    CustomRule(
        name="private-key",
        description="Private key in code",
        pattern=r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
        message="Private key found in code - never commit private keys",
        severity=RuleSeverity.CRITICAL,
    ),
    CustomRule(
        name="jwt-token",
        description="JWT token in code",
        pattern=r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        message="JWT token found in code - tokens should not be hardcoded",
        severity=RuleSeverity.WARNING,
    ),
]


# Python best practices
PYTHON_BEST_PRACTICES = [
    CustomRule(
        name="print-statement",
        description="Print statement in production code",
        pattern=r'^\s*print\s*\(',
        message="Remove print statements - use logging instead",
        severity=RuleSeverity.WARNING,
        file_patterns=[r'.*\.py$'],
    ),
    CustomRule(
        name="bare-except",
        description="Bare except clause",
        pattern=r'except\s*:',
        message="Avoid bare except - catch specific exceptions",
        severity=RuleSeverity.WARNING,
        file_patterns=[r'.*\.py$'],
    ),
    CustomRule(
        name="mutable-default-arg",
        description="Mutable default argument",
        pattern=r'def\s+\w+\([^)]*=\s*(\[\]|\{\})',
        message="Mutable default argument - use None and initialize inside function",
        severity=RuleSeverity.WARNING,
        file_patterns=[r'.*\.py$'],
    ),
    CustomRule(
        name="assert-in-production",
        description="Assert statement (disabled in production)",
        pattern=r'^\s*assert\s+',
        message="Assert is disabled with -O flag - use proper validation",
        severity=RuleSeverity.INFO,
        file_patterns=[r'.*\.py$'],
    ),
    CustomRule(
        name="todo-comment",
        description="TODO comment",
        pattern=r'#\s*(TODO|FIXME|XXX|HACK):?',
        message="TODO comment found - consider resolving before merging",
        severity=RuleSeverity.INFO,
        file_patterns=[r'.*\.py$'],
    ),
]


# JavaScript/TypeScript best practices
JAVASCRIPT_BEST_PRACTICES = [
    CustomRule(
        name="console-log",
        description="Console.log in production",
        pattern=r'console\.(log|debug|info)\s*\(',
        message="Remove console.log - use proper logging",
        severity=RuleSeverity.WARNING,
        file_patterns=[r'.*\.(js|ts|jsx|tsx)$'],
    ),
    CustomRule(
        name="alert-usage",
        description="Alert usage",
        pattern=r'\balert\s*\(',
        message="Remove alert() - use proper UI feedback",
        severity=RuleSeverity.WARNING,
        file_patterns=[r'.*\.(js|ts|jsx|tsx)$'],
    ),
    CustomRule(
        name="any-type",
        description="Any type usage in TypeScript",
        pattern=r':\s*any\b',
        message="Avoid any type - use proper typing",
        severity=RuleSeverity.INFO,
        file_patterns=[r'.*\.ts$', r'.*\.tsx$'],
    ),
    CustomRule(
        name="var-usage",
        description="var keyword usage",
        pattern=r'\bvar\s+\w+',
        message="Use const or let instead of var",
        severity=RuleSeverity.WARNING,
        file_patterns=[r'.*\.(js|ts|jsx|tsx)$'],
    ),
    CustomRule(
        name="todo-comment-js",
        description="TODO comment",
        pattern=r'//\s*(TODO|FIXME|XXX|HACK):?',
        message="TODO comment found - consider resolving before merging",
        severity=RuleSeverity.INFO,
        file_patterns=[r'.*\.(js|ts|jsx|tsx)$'],
    ),
]


# Minimal ruleset - just security essentials
MINIMAL = [
    CustomRule(
        name="hardcoded-secret",
        description="Hardcoded secret detection",
        pattern=r'(?i)(password|secret|api[_-]?key|token)\s*=\s*["\'][^"\']{8,}["\']',
        message="Potential hardcoded secret - use environment variables",
        severity=RuleSeverity.CRITICAL,
    ),
]


# All presets
PRESETS = {
    "security-strict": SECURITY_STRICT,
    "python": PYTHON_BEST_PRACTICES,
    "javascript": JAVASCRIPT_BEST_PRACTICES,
    "minimal": MINIMAL,
    "all": SECURITY_STRICT + PYTHON_BEST_PRACTICES + JAVASCRIPT_BEST_PRACTICES,
}


def get_preset(name: str) -> list[CustomRule]:
    """
    Get a preset ruleset by name.
    
    Available presets:
    - security-strict: Security-focused rules
    - python: Python best practices
    - javascript: JavaScript/TypeScript best practices
    - minimal: Just security essentials
    - all: All rules combined
    
    Args:
        name: Preset name
        
    Returns:
        List of CustomRule objects
        
    Raises:
        ValueError: If preset not found
    """
    if name not in PRESETS:
        available = ", ".join(PRESETS.keys())
        raise ValueError(f"Unknown preset '{name}'. Available: {available}")
    
    return PRESETS[name].copy()


def list_presets() -> dict[str, int]:
    """List all available presets with rule counts."""
    return {name: len(rules) for name, rules in PRESETS.items()}
