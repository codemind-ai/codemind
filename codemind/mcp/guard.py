"""CodeMind Guardian system for security and quality assurance.

This module provides comprehensive security vulnerability detection including:
- SQL Injection
- XSS (Cross-Site Scripting)
- Command Injection
- Path Traversal
- Credential Exposure
- Unsafe Deserialization
- CSRF vulnerabilities
- And more...

Each issue includes auto-fix suggestions for immediate remediation.
"""

import re
import functools
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Tuple

from ..rules.engine import RuleEngine, RuleMatch, RuleSeverity
from ..rules.presets import get_preset
from ..analysis.ast_engine import ASTAnalyzer, Finding as ASTFinding


class GuardType(Enum):
    SECURITY = "security"
    QUALITY = "quality"
    AI_SLOP = "ai_slop"


@functools.lru_cache(maxsize=256)
def _compile_pattern(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern:
    """Compile and cache regex patterns for performance."""
    return re.compile(pattern, flags)


@dataclass
class GuardIssue:
    """Represents a detected issue with remediation information."""
    type: GuardType
    severity: RuleSeverity
    message: str
    file: Optional[str] = None
    line: Optional[int] = None
    code_snippet: Optional[str] = None
    suggestion: Optional[str] = None
    auto_fix: Optional[str] = None
    explanation: Optional[str] = None
    vulnerability_type: Optional[str] = None  # SQL_INJECTION, XSS, etc.


@dataclass
class GuardReport:
    """Complete audit report with score and categorized issues."""
    issues: List[GuardIssue] = field(default_factory=list)
    score: int = 100  # 0-100, where 100 is perfect
    
    @property
    def is_safe(self) -> bool:
        """Returns False if any critical security issues exist."""
        return not any(i.severity == RuleSeverity.CRITICAL for i in self.issues)
    
    @property
    def is_clean(self) -> bool:
        """Returns True if code meets quality threshold."""
        return self.score >= 80
    
    @property
    def security_issues(self) -> List[GuardIssue]:
        """Get only security-related issues."""
        return [i for i in self.issues if i.type == GuardType.SECURITY]
    
    @property
    def quality_issues(self) -> List[GuardIssue]:
        """Get only quality-related issues."""
        return [i for i in self.issues if i.type in (GuardType.QUALITY, GuardType.AI_SLOP)]
    
    def get_fixed_code(self, original_code: str) -> str:
        """Apply all auto-fixes to the code."""
        fixed = original_code
        # Sort by line number descending to preserve line numbers during replacement
        fixable = sorted(
            [i for i in self.issues if i.auto_fix and i.code_snippet],
            key=lambda x: x.line or 0,
            reverse=True
        )
        for issue in fixable:
            if issue.code_snippet and issue.auto_fix:
                fixed = fixed.replace(issue.code_snippet, issue.auto_fix)
        return fixed


# SECURITY PATTERNS
# Common security vulnerability signatures for multi-language detection
SECURITY_PATTERNS: List[Tuple[str, str, RuleSeverity, str, str, str]] = [
    # SQL INJECTION PATTERNS
    # Pattern, Message, Severity, Suggestion, AutoFix hint, Vulnerability type
    
    # Python SQL Injection
    (r'cursor\.execute\s*\(\s*[f"\'].*%s.*["\'].*%',
     "SQL Injection: String formatting in query",
     RuleSeverity.CRITICAL,
     "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
     None,
     "SQL_INJECTION"),
    
    (r'cursor\.execute\s*\(\s*f["\']',
     "SQL Injection: f-string in SQL query",
     RuleSeverity.CRITICAL,
     "NEVER use f-strings in SQL. Use parameterized queries with placeholders",
     None,
     "SQL_INJECTION"),
    
    (r'\.execute\s*\(\s*["\'].*\+.*["\']',
     "SQL Injection: String concatenation in query",
     RuleSeverity.CRITICAL,
     "Use parameterized queries instead of string concatenation",
     None,
     "SQL_INJECTION"),
    
    (r'\.execute\s*\(\s*.*\.format\s*\(',
     "SQL Injection: .format() in SQL query",
     RuleSeverity.CRITICAL,
     "Replace .format() with parameterized query placeholders",
     None,
     "SQL_INJECTION"),
    
    (r'\.executemany\s*\(\s*f["\']',
     "SQL Injection: f-string in executemany",
     RuleSeverity.CRITICAL,
     "Use parameterized queries with executemany",
     None,
     "SQL_INJECTION"),
     
    # JavaScript/Node SQL Injection
    (r'query\s*\(\s*[`"\'].*\$\{',
     "SQL Injection: Template literal in query",
     RuleSeverity.CRITICAL,
     "Use parameterized queries: query('SELECT * FROM users WHERE id = $1', [userId])",
     None,
     "SQL_INJECTION"),
    
    (r'mysql\.query\s*\(\s*["\'].*\+',
     "SQL Injection: Concatenation in MySQL query",
     RuleSeverity.CRITICAL,
     "Use mysql.query('SELECT ? FROM ??', [value, table])",
     None,
     "SQL_INJECTION"),
    
    # XSS (Cross-Site Scripting) PATTERNS
    (r'innerHTML\s*=\s*[^"\'`]*(?:user|input|req\.|request|params)',
     "XSS: User input assigned to innerHTML",
     RuleSeverity.CRITICAL,
     "Use textContent instead, or sanitize with DOMPurify.sanitize()",
     None,
     "XSS"),
    
    (r'document\.write\s*\(.*(?:user|input|req\.|request|params)',
     "XSS: User input in document.write",
     RuleSeverity.CRITICAL,
     "Avoid document.write with user input. Use DOM methods with textContent",
     None,
     "XSS"),
    
    (r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:',
     "XSS: dangerouslySetInnerHTML usage detected",
     RuleSeverity.WARNING,
     "Ensure content is sanitized with DOMPurify before using dangerouslySetInnerHTML",
     None,
     "XSS"),
    
    (r'\.html\s*\(\s*(?:user|input|req\.|request|params|\$)',
     "XSS: jQuery .html() with potential user input",
     RuleSeverity.CRITICAL,
     "Use .text() instead, or sanitize input before using .html()",
     None,
     "XSS"),
    
    (r'v-html\s*=',
     "XSS: Vue v-html directive (potential XSS)",
     RuleSeverity.WARNING,
     "Avoid v-html with user input. Use v-text or sanitize content",
     None,
     "XSS"),
    
    # Python XSS (Flask/Django)
    (r'\|\s*safe\b',
     "XSS: Django/Jinja2 |safe filter bypasses escaping",
     RuleSeverity.WARNING,
     "Only use |safe with trusted, sanitized content",
     None,
     "XSS"),
    
    (r'Markup\s*\(',
     "XSS: Flask Markup() bypasses escaping",
     RuleSeverity.WARNING,
     "Only use Markup() with sanitized content",
     None,
     "XSS"),
    
    # COMMAND INJECTION PATTERNS
    (r'os\.system\s*\(',
     "Command Injection: os.system is dangerous",
     RuleSeverity.CRITICAL,
     "Use subprocess.run() with shell=False and list arguments",
     None,
     "COMMAND_INJECTION"),
    
    (r'subprocess\.\w+\s*\([^)]*shell\s*=\s*True',
     "Command Injection: subprocess with shell=True",
     RuleSeverity.CRITICAL,
     "Set shell=False and pass command as list: subprocess.run(['cmd', 'arg'])",
     None,
     "COMMAND_INJECTION"),
    
    (r'exec\s*\(\s*(?:user|input|req\.|request|params)',
     "Command Injection: exec() with user input",
     RuleSeverity.CRITICAL,
     "Never use exec() with user-controlled input",
     None,
     "COMMAND_INJECTION"),
    
    (r'child_process\.exec\s*\(',
     "Command Injection: child_process.exec is dangerous",
     RuleSeverity.WARNING,
     "Use child_process.execFile or spawn with array arguments",
     None,
     "COMMAND_INJECTION"),
    
    # PATH TRAVERSAL PATTERNS
    (r'open\s*\(\s*(?:user|input|req\.|request|params)',
     "Path Traversal: User input in file path",
     RuleSeverity.CRITICAL,
     "Validate and sanitize file paths. Use os.path.basename() or pathlib",
     None,
     "PATH_TRAVERSAL"),
    
    (r'\.\./',
     "Path Traversal: Directory traversal sequence detected",
     RuleSeverity.WARNING,
     "Sanitize paths to prevent directory traversal attacks",
     None,
     "PATH_TRAVERSAL"),
    
    (r'path\.join\s*\([^)]*(?:user|input|req\.|request|params)',
     "Path Traversal: User input in path.join",
     RuleSeverity.WARNING,
     "Validate user input doesn't contain '..' before joining paths",
     None,
     "PATH_TRAVERSAL"),
    
    # UNSAFE DESERIALIZATION
    (r'pickle\.loads?\s*\(',
     "Unsafe Deserialization: pickle with untrusted data",
     RuleSeverity.CRITICAL,
     "Never unpickle untrusted data. Use JSON or safe alternatives",
     None,
     "UNSAFE_DESERIALIZATION"),
    
    (r'yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)',
     "Unsafe Deserialization: yaml.load without SafeLoader",
     RuleSeverity.CRITICAL,
     "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
     None,
     "UNSAFE_DESERIALIZATION"),
    
    (r'marshal\.loads?\s*\(',
     "Unsafe Deserialization: marshal with untrusted data",
     RuleSeverity.CRITICAL,
     "Never use marshal with untrusted data",
     None,
     "UNSAFE_DESERIALIZATION"),
    
    (r'JSON\.parse\s*\(\s*(?:user|input|req\.|request)',
     "Untrusted JSON: Parsing user input directly",
     RuleSeverity.WARNING,
     "Validate JSON structure after parsing",
     None,
     "UNSAFE_DESERIALIZATION"),
    
    # CREDENTIAL EXPOSURE
    (r'(?:password|passwd|pwd|secret|api_key|apikey|token|auth)\s*=\s*["\'][^"\']{4,}["\']',
     "Credential Exposure: Hardcoded secret detected",
     RuleSeverity.CRITICAL,
     "Use environment variables: os.environ.get('SECRET_KEY')",
     None,
     "CREDENTIAL_EXPOSURE"),
    
    (r'(?:AWS_SECRET|PRIVATE_KEY|DATABASE_URL)\s*=\s*["\']',
     "Credential Exposure: Hardcoded cloud credential",
     RuleSeverity.CRITICAL,
     "Store in environment variables or secret manager",
     None,
     "CREDENTIAL_EXPOSURE"),
    
    (r'Bearer\s+[a-zA-Z0-9_\-\.]{20,}',
     "Credential Exposure: Hardcoded Bearer token",
     RuleSeverity.CRITICAL,
     "Load tokens from environment variables",
     None,
     "CREDENTIAL_EXPOSURE"),
    
    # INSECURE CRYPTOGRAPHY
    (r'md5\s*\(|MD5\s*\(',
     "Weak Crypto: MD5 is cryptographically broken",
     RuleSeverity.WARNING,
     "Use SHA-256 or better: hashlib.sha256()",
     None,
     "WEAK_CRYPTO"),
    
    (r'sha1\s*\(|SHA1\s*\(',
     "Weak Crypto: SHA1 is deprecated",
     RuleSeverity.WARNING,
     "Use SHA-256 or better for security purposes",
     None,
     "WEAK_CRYPTO"),
    
    (r'DES\s*\(|\.DES\b',
     "Weak Crypto: DES is insecure",
     RuleSeverity.CRITICAL,
     "Use AES-256 or ChaCha20 instead",
     None,
     "WEAK_CRYPTO"),
    
    # INSECURE RANDOMNESS
    (r'random\.random\s*\(|Math\.random\s*\(',
     "Insecure Random: Not suitable for security",
     RuleSeverity.WARNING,
     "Use secrets.token_bytes() or crypto.randomBytes() for security",
     None,
     "INSECURE_RANDOM"),
    
    # DANGEROUS FUNCTIONS
    (r'\beval\s*\(',
     "Dangerous: eval() can execute arbitrary code",
     RuleSeverity.CRITICAL,
     "Avoid eval(). Use ast.literal_eval() for Python or JSON.parse() for JS",
     None,
     "DANGEROUS_FUNCTION"),
    
    (r'Function\s*\(\s*["\']',
     "Dangerous: Function constructor with string",
     RuleSeverity.CRITICAL,
     "Avoid dynamic function creation from strings",
     None,
     "DANGEROUS_FUNCTION"),
    
    (r'__import__\s*\(\s*(?:user|input|req\.|request)',
     "Dangerous: Dynamic import with user input",
     RuleSeverity.CRITICAL,
     "Never use dynamic imports with user input",
     None,
     "DANGEROUS_FUNCTION"),
    
    # SSRF (Server-Side Request Forgery)
    (r'requests\.(get|post|put|delete)\s*\(\s*(?:user|input|req\.|request|params)',
     "SSRF: User-controlled URL in HTTP request",
     RuleSeverity.CRITICAL,
     "Validate and whitelist allowed URLs/domains",
     None,
     "SSRF"),
    
    (r'fetch\s*\(\s*(?:user|input|req\.|request|params)',
     "SSRF: User input in fetch URL",
     RuleSeverity.CRITICAL,
     "Validate URL against whitelist before fetching",
     None,
     "SSRF"),
    
    (r'urllib\.request\.urlopen\s*\(',
     "SSRF: urlopen with potential user input",
     RuleSeverity.WARNING,
     "Validate URLs against whitelist",
     None,
     "SSRF"),
    
    # CORS MISCONFIGURATION
    (r'Access-Control-Allow-Origin["\']?\s*:\s*["\']?\*',
     "CORS: Wildcard origin allows any domain",
     RuleSeverity.WARNING,
     "Specify allowed origins explicitly",
     None,
     "CORS_MISCONFIGURATION"),
    
    (r'cors\s*\(\s*\{\s*origin\s*:\s*true',
     "CORS: Reflecting origin is dangerous with credentials",
     RuleSeverity.WARNING,
     "Whitelist specific origins instead of reflecting",
     None,
     "CORS_MISCONFIGURATION"),
    
    # MISSING SECURITY HEADERS
    (r'app\.disable\s*\(\s*["\']x-powered-by["\']\s*\)',
     "Good: Disabling x-powered-by header",
     RuleSeverity.INFO,
     None,
     None,
     "SECURITY_HEADER"),
    
    # OPEN REDIRECT
    (r'redirect\s*\(\s*(?:user|input|req\.|request|params)',
     "Open Redirect: User input in redirect",
     RuleSeverity.CRITICAL,
     "Validate redirect URLs against whitelist",
     None,
     "OPEN_REDIRECT"),
    
    (r'window\.location\s*=\s*(?:user|input|req\.|request|params)',
     "Open Redirect: User-controlled redirect",
     RuleSeverity.CRITICAL,
     "Validate redirect destination",
     None,
     "OPEN_REDIRECT"),
    
    # LDAP INJECTION
    (r'ldap\.\w+\s*\([^)]*(?:user|input|req\.|request)',
     "LDAP Injection: User input in LDAP query",
     RuleSeverity.CRITICAL,
     "Escape LDAP special characters in user input",
     None,
     "LDAP_INJECTION"),
    
    # REGEX DOS
    (r're\.compile\s*\([^)]*(?:\.\*){2,}',
     "ReDoS: Potentially vulnerable regex pattern",
     RuleSeverity.WARNING,
     "Avoid nested quantifiers in regex. Use possessive quantifiers or atomic groups",
     None,
     "REGEX_DOS"),
    
    # RACE CONDITIONS
    (r'if\s+os\.path\.exists.*\n.*open\s*\(',
     "Race Condition: TOCTOU vulnerability",
     RuleSeverity.WARNING,
     "Use try/except instead of check-then-use patterns",
     None,
     "RACE_CONDITION"),
]


class SecurityGuard:
    """Guards against security vulnerabilities with auto-fix suggestions."""
    
    def __init__(self):
        self.engine = RuleEngine()
        self.engine.add_rules(get_preset("security-strict"))
        self._patterns = [
            (_compile_pattern(p[0]), p[1], p[2], p[3], p[4], p[5])
            for p in SECURITY_PATTERNS
        ]
    
    def audit(self, code: str, filename: str = "unknown") -> List[GuardIssue]:
        """Audit code for security vulnerabilities."""
        issues = []
        lines = code.splitlines()
        
        # Check with rule engine
        matches = self.engine.evaluate_file(filename, code)
        for m in matches:
            issues.append(GuardIssue(
                type=GuardType.SECURITY,
                severity=m.rule.severity,
                message=m.rule.message or m.rule.description,
                file=filename,
                line=m.line,
                code_snippet=m.matched_text,
                suggestion=m.rule.message
            ))
        
        # Check security patterns
        for i, line in enumerate(lines, 1):
            for pattern, msg, severity, suggestion, auto_fix, vuln_type in self._patterns:
                if pattern.search(line):
                    issues.append(GuardIssue(
                        type=GuardType.SECURITY,
                        severity=severity,
                        message=msg,
                        file=filename,
                        line=i,
                        code_snippet=line.strip(),
                        suggestion=suggestion,
                        auto_fix=auto_fix,
                        vulnerability_type=vuln_type,
                        explanation=f"This pattern is commonly associated with {vuln_type.replace('_', ' ')} attacks."
                    ))
        
        return issues


# AI SLOP PATTERNS
# Quality and clean code signatures to reduce AI-generated noise
AI_SLOP_PATTERNS: List[Tuple[str, str, RuleSeverity, Optional[str]]] = [
    # Redundant comments (AI loves these)
    (r"//\s*This function (adds|subtracts|multiplies|divides|returns|creates|gets|sets)", 
     "Redundant comment explaining obvious behavior", RuleSeverity.INFO, None),
    (r"//\s*(Loop|Iterate) (through|over) (the|all)", 
     "Redundant comment describing loop", RuleSeverity.INFO, None),
    (r"//\s*(Check|Verify) if", 
     "Redundant comment describing condition", RuleSeverity.INFO, None),
    (r"//\s*Initialize|//\s*Declare|//\s*Define", 
     "Redundant initialization comment", RuleSeverity.INFO, None),
    (r"//\s*Return the result", 
     "Redundant return comment", RuleSeverity.INFO, None),
    (r"//\s*Import (the|necessary)", 
     "Redundant import comment", RuleSeverity.INFO, None),
    (r"//\s*Create (a|an|the) (new )?instance", 
     "Redundant instantiation comment", RuleSeverity.INFO, None),
    
    # AI meta-comments
    (r"//.*as an AI (assistant|language model)", 
     "AI-typical meta-comment (remove)", RuleSeverity.WARNING, None),
    (r"//.*I (cannot|can't|don't have)", 
     "AI self-reference comment", RuleSeverity.WARNING, None),
    (r"#.*AI-generated|#.*Generated by", 
     "AI attribution comment", RuleSeverity.INFO, None),
    (r"//\s*Note:|#\s*Note:", 
     "Potentially unnecessary 'Note:' comment", RuleSeverity.INFO, None),
    
    # Verbose docstrings
    (r'""".*This (class|function|method) (represents|implements|creates|is used to)', 
     "Verbose docstring - be more concise", RuleSeverity.INFO, None),
    (r"/\*\*.*This class represents", 
     "Verbose Javadoc", RuleSeverity.INFO, None),
    (r'""".*Args:(\s*\n\s*\w+:.*){6,}',
     "Overly detailed docstring - consider simplifying", RuleSeverity.INFO, None),
    
    # Generic variable names (with auto-fix suggestions)
    (r"\b(temp\d*|tmp\d*)\s*=", 
     "Generic 'temp' variable name", RuleSeverity.INFO, "Use descriptive name like 'tempBuffer' or 'cachedValue'"),
    (r"\bdata\s*=\s*", 
     "Generic 'data' variable name - be specific", RuleSeverity.INFO, "Use 'userData', 'responseData', 'configData'"),
    (r"\bresult\s*=\s*", 
     "Generic 'result' variable - use descriptive name", RuleSeverity.INFO, "Use 'validationResult', 'calculatedTotal'"),
    (r"\bval\s*=\s*", 
     "Generic 'val' variable - use descriptive name", RuleSeverity.INFO, "Rename to describe the value's purpose"),
    (r"\bobj\s*=\s*", 
     "Generic 'obj' variable - use descriptive name", RuleSeverity.INFO, "Rename to describe the object type"),
    (r"\bhandler\s*=\s*", 
     "Generic 'handler' variable - specify what it handles", RuleSeverity.INFO, "Use 'clickHandler', 'errorHandler'"),
    (r"\bitem\s+in\s+items", 
     "Generic 'item/items' naming - be specific", RuleSeverity.INFO, "Use 'user in users', 'order in orders'"),
    (r"\bx\s*=\s*|,\s*x\s*\)|,\s*x\s*,", 
     "Single-letter variable 'x' - use descriptive name", RuleSeverity.INFO, None),
    (r"\bi\s*=\s*0|for\s+i\s+in", 
     "Index variable 'i' - consider descriptive names for complex loops", RuleSeverity.INFO, None),
    
    # Debug/logging leftovers
    (r"\bprint\s*\(", 
     "Print statement - remove before production", RuleSeverity.WARNING, "# Remove or use proper logging"),
    (r"console\.(log|warn|error)\s*\(", 
     "Console statement - remove before production", RuleSeverity.WARNING, "// Remove or use proper logger"),
    (r"//\s*TODO:|#\s*TODO:", 
     "Unresolved TODO comment", RuleSeverity.INFO, None),
    (r"//\s*FIXME:|#\s*FIXME:", 
     "Unresolved FIXME comment", RuleSeverity.WARNING, None),
    (r"//\s*HACK:|#\s*HACK:", 
     "Unresolved HACK comment", RuleSeverity.WARNING, None),
    (r"//\s*XXX:|#\s*XXX:", 
     "Unresolved XXX marker", RuleSeverity.WARNING, None),
    (r"debugger;", 
     "Debugger statement left in code", RuleSeverity.WARNING, "// Remove debugger statement"),
    (r"breakpoint\s*\(\)", 
     "Python breakpoint() in code", RuleSeverity.WARNING, "# Remove breakpoint()"),
    
    # Decorative/unnecessary comments
    (r"//\s*-{3,}|#\s*-{3,}", 
     "Decorative comment divider - remove or make meaningful", RuleSeverity.INFO, None),
    (r"//\s*\*{3,}|#\s*\*{3,}", 
     "Decorative comment divider - remove or make meaningful", RuleSeverity.INFO, None),
    (r"//\s*={3,}|#\s*={3,}", 
     "Decorative separator - consider removing", RuleSeverity.INFO, None),
    
    # Common AI anti-patterns
    (r"catch\s*\(\s*\w+\s*\)\s*{\s*}", 
     "Empty catch block - handle errors properly", RuleSeverity.WARNING, "// Log error or handle appropriately"),
    (r"except:\s*$|except\s+Exception:", 
     "Bare except clause - be specific about exceptions", RuleSeverity.WARNING, "# Catch specific exceptions"),
    (r"except\s+Exception\s+as\s+e:\s*\n\s*pass", 
     "Swallowing exceptions silently", RuleSeverity.WARNING, "# At minimum, log the exception"),
    (r"# type: ignore", 
     "Type ignore directive - fix the type issue instead", RuleSeverity.INFO, None),
    (r"@ts-ignore|@ts-nocheck", 
     "TypeScript ignore - fix the type issue", RuleSeverity.INFO, None),
    (r"eslint-disable", 
     "ESLint disable - consider fixing the issue", RuleSeverity.INFO, None),
    (r"noqa", 
     "noqa directive - consider fixing the linting issue", RuleSeverity.INFO, None),
    
    # Callback hell / promise chains
    (r"\.then\s*\([^)]*\.then\s*\([^)]*\.then", 
     "Promise chain too deep - use async/await", RuleSeverity.INFO, "Refactor to async/await"),
    
    # Magic numbers
    (r"if\s+\w+\s*[<>=!]+\s*[0-9]{2,}(?!\d*\s*[/*%])", 
     "Magic number in condition - use named constant", RuleSeverity.INFO, "Extract to named constant"),
    
    # Long functions (heuristic)
    (r"^(def|function|async function)\s+\w+",
     "Function definition - ensure it's not too long", RuleSeverity.INFO, None),
    
    # Mutable default arguments (Python)
    (r"def\s+\w+\s*\([^)]*=\s*\[\s*\]", 
     "Mutable default argument [] - use None instead", RuleSeverity.WARNING, "def func(arg=None); if arg is None: arg = []"),
    (r"def\s+\w+\s*\([^)]*=\s*\{\s*\}", 
     "Mutable default argument {} - use None instead", RuleSeverity.WARNING, "def func(arg=None); if arg is None: arg = {}"),
    
    # var usage in JavaScript
    (r"\bvar\s+\w+\s*=", 
     "Using 'var' - prefer 'const' or 'let'", RuleSeverity.INFO, "Replace with const or let"),
]


class QualityGuard:
    """Guards against poor code quality and 'AI Slop'."""
    
    def __init__(self):
        self._patterns = [
            (_compile_pattern(p[0]), p[1], p[2], p[3])
            for p in AI_SLOP_PATTERNS
        ]
    
    def audit(self, code: str, filename: str = "unknown") -> List[GuardIssue]:
        """Audit code for quality issues and AI slop."""
        issues = []
        lines = code.splitlines()
        
        for i, line in enumerate(lines, 1):
            for pattern, msg, severity, suggestion in self._patterns:
                if pattern.search(line):
                    issues.append(GuardIssue(
                        type=GuardType.AI_SLOP,
                        severity=severity,
                        message=msg,
                        file=filename,
                        line=i,
                        code_snippet=line.strip(),
                        suggestion=suggestion
                    ))
        
        return issues


class Guardian:
    """Main orchestrator for comprehensive code auditing."""
    
    def __init__(self):
        self.security_guard = SecurityGuard()
        self.quality_guard = QualityGuard()
    
    def audit(self, code: str, filename: str = "unknown") -> GuardReport:
        """Run complete security and quality audit."""
        issues = []
        issues.extend(self.security_guard.audit(code, filename))
        issues.extend(self.quality_guard.audit(code, filename))
        
        # Add AST-based analysis (Phase E1)
        try:
            # Determine language from filename extension or default to python
            language = "python"
            if filename.endswith(".js") or filename.endswith(".ts"):
                language = "javascript"
            
            ast_analyzer = ASTAnalyzer()
            ast_findings = ast_analyzer.analyze(code, language)
            
            for f in ast_findings:
                severity_map = {
                    "CRITICAL": RuleSeverity.CRITICAL,
                    "HIGH": RuleSeverity.HIGH,
                    "MEDIUM": RuleSeverity.MEDIUM,
                    "LOW": RuleSeverity.LOW,
                    "INFO": RuleSeverity.INFO
                }
                
                issue = GuardIssue(
                    type=GuardType.SECURITY,
                    severity=severity_map.get(f.severity, RuleSeverity.MEDIUM),
                    message=f.message,
                    file=filename,
                    line=f.line,
                    code_snippet=None, # AST findings might not have snippet yet
                    suggestion=f.suggestion,
                    vulnerability_type=f.type,
                    explanation=f"{f.owasp_category} ({f.cwe_id})" if f.cwe_id else None
                )
                
                # Deduplicate with regex findings
                is_duplicate = any(
                    i.vulnerability_type == issue.vulnerability_type and i.line == issue.line 
                    for i in issues
                )
                if not is_duplicate:
                    issues.append(issue)
        except Exception:
            pass

        # Calculate score with weighted penalties
        score = 100
        for issue in issues:
            if issue.severity == RuleSeverity.CRITICAL:
                score -= 25  # Critical issues are very costly
            elif issue.severity == RuleSeverity.WARNING:
                score -= 10
            elif issue.severity == RuleSeverity.HIGH:
                score -= 20
            elif issue.severity == RuleSeverity.MEDIUM:
                score -= 10
            else:
                score -= 2
        
        report = GuardReport(issues=issues, score=max(0, score))
        return report
    
    def audit_and_fix(self, code: str, filename: str = "unknown") -> Tuple[GuardReport, str]:
        """Audit code and return both report and auto-fixed code."""
        report = self.audit(code, filename)
        fixed_code = report.get_fixed_code(code)
        return report, fixed_code
    
    def get_vulnerability_summary(self, report: GuardReport) -> Dict[str, List[GuardIssue]]:
        """Group issues by vulnerability type."""
        summary: Dict[str, List[GuardIssue]] = {}
        for issue in report.security_issues:
            vuln_type = issue.vulnerability_type or "OTHER"
            if vuln_type not in summary:
                summary[vuln_type] = []
            summary[vuln_type].append(issue)
        return summary
