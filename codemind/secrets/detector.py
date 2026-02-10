"""Advanced secrets detection engine.

Detects 30+ types of API keys, tokens, and credentials using:
1. Known service patterns (high precision)
2. Shannon entropy analysis (catches unknown secrets)
3. Context-aware false positive filtering

No external dependencies required.
"""

import re
import math
import functools
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Tuple
from pathlib import Path


class SecretSeverity(Enum):
    """Severity levels for secret findings."""
    CRITICAL = "critical"    # Active credentials that grant access
    HIGH = "high"            # Tokens/keys that could be exploited
    MEDIUM = "medium"        # Potentially sensitive values
    LOW = "low"              # Informational findings
    INFO = "info"            # FYI, might not be real secret


@dataclass
class SecretFinding:
    """Represents a detected secret."""
    type: str                    # Secret type ID (e.g., "aws_access_key")
    service: str                 # Service name (e.g., "AWS", "GitHub")
    severity: SecretSeverity
    message: str                 # Human-readable description
    line: int                    # Line number (1-indexed)
    column: int                  # Column where secret starts
    matched_text: str            # The matched text (partially redacted)
    raw_length: int              # Length of the actual secret
    file: Optional[str] = None
    suggestion: str = ""         # Remediation suggestion
    entropy: Optional[float] = None  # Shannon entropy if applicable
    cwe_id: str = "CWE-798"     # Use of Hardcoded Credentials

    @property
    def redacted(self) -> str:
        """Return a redacted version of the matched text."""
        if len(self.matched_text) <= 8:
            return "***REDACTED***"
        return self.matched_text[:4] + "*" * (len(self.matched_text) - 8) + self.matched_text[-4:]


@functools.lru_cache(maxsize=256)
def _compile(pattern: str, flags: int = 0) -> re.Pattern:
    """Compile and cache regex patterns."""
    return re.compile(pattern, flags)


# ─────────────────────────────────────────────────────────
# KNOWN SECRET PATTERNS — organized by service
# Each tuple: (pattern, type_id, service, severity, message, suggestion)
# ─────────────────────────────────────────────────────────

KNOWN_PATTERNS: List[Tuple[str, str, str, SecretSeverity, str, str]] = [
    # ── AWS ──
    (r'AKIA[0-9A-Z]{16}',
     "aws_access_key_id", "AWS", SecretSeverity.CRITICAL,
     "AWS Access Key ID detected",
     "Remove this key immediately. Rotate it in AWS IAM Console and use environment variables or AWS credentials file."),

    (r'(?i)(?:aws_secret_access_key|aws_secret)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
     "aws_secret_key", "AWS", SecretSeverity.CRITICAL,
     "AWS Secret Access Key detected",
     "Rotate this key immediately in AWS IAM. Use environment variables: AWS_SECRET_ACCESS_KEY"),

    (r'(?i)(?:ASIA[0-9A-Z]{16})',
     "aws_session_token", "AWS", SecretSeverity.HIGH,
     "AWS Session/Temporary Token detected",
     "Temporary tokens should never be committed. Use AWS STS assume-role at runtime."),

    # ── GitHub ──
    (r'ghp_[A-Za-z0-9_]{36,}',
     "github_pat", "GitHub", SecretSeverity.CRITICAL,
     "GitHub Personal Access Token (classic) detected",
     "Revoke token at github.com/settings/tokens. Use GITHUB_TOKEN env var or fine-grained tokens with minimal scopes."),

    (r'github_pat_[A-Za-z0-9_]{82,}',
     "github_fine_grained", "GitHub", SecretSeverity.CRITICAL,
     "GitHub Fine-Grained Personal Access Token detected",
     "Revoke at github.com/settings/tokens. Use GITHUB_TOKEN env var."),

    (r'gho_[A-Za-z0-9_]{36,}',
     "github_oauth", "GitHub", SecretSeverity.HIGH,
     "GitHub OAuth Access Token detected",
     "Revoke this token. OAuth tokens should be obtained at runtime, not hardcoded."),

    (r'ghu_[A-Za-z0-9_]{36,}',
     "github_user_token", "GitHub", SecretSeverity.HIGH,
     "GitHub User-to-Server Token detected",
     "Revoke this token and use proper OAuth flow."),

    (r'ghs_[A-Za-z0-9_]{36,}',
     "github_server_token", "GitHub", SecretSeverity.HIGH,
     "GitHub Server-to-Server Token detected",
     "This token should never be in source code. Use GitHub App authentication at runtime."),

    (r'ghr_[A-Za-z0-9_]{36,}',
     "github_refresh_token", "GitHub", SecretSeverity.HIGH,
     "GitHub Refresh Token detected",
     "Revoke immediately. Refresh tokens must be stored securely, not in source."),

    # ── GitLab ──
    (r'glpat-[A-Za-z0-9\-_]{20,}',
     "gitlab_pat", "GitLab", SecretSeverity.CRITICAL,
     "GitLab Personal Access Token detected",
     "Revoke at gitlab.com/-/profile/personal_access_tokens. Use CI/CD variables."),

    (r'glrt-[A-Za-z0-9\-_]{20,}',
     "gitlab_runner_token", "GitLab", SecretSeverity.HIGH,
     "GitLab Runner Registration Token detected",
     "Rotate this token in GitLab CI/CD settings."),

    # ── Slack ──
    (r'xox[baprs]-[A-Za-z0-9\-]{10,250}',
     "slack_token", "Slack", SecretSeverity.CRITICAL,
     "Slack Token detected (bot/app/user)",
     "Revoke at api.slack.com/apps. Use environment variables for Slack tokens."),

    (r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}',
     "slack_webhook", "Slack", SecretSeverity.HIGH,
     "Slack Webhook URL detected",
     "Rotate webhook at api.slack.com. Store in env: SLACK_WEBHOOK_URL"),

    # ── Stripe ──
    (r'sk_(live|test)_[A-Za-z0-9]{24,}',
     "stripe_secret_key", "Stripe", SecretSeverity.CRITICAL,
     "Stripe Secret Key detected",
     "Rotate at dashboard.stripe.com/apikeys. NEVER use live keys in code. Use STRIPE_SECRET_KEY env var."),

    (r'pk_(live|test)_[A-Za-z0-9]{24,}',
     "stripe_publishable_key", "Stripe", SecretSeverity.LOW,
     "Stripe Publishable Key detected (generally safe for frontend)",
     "Publishable keys are okay in frontend code but should not contain test keys in production."),

    (r'rk_(live|test)_[A-Za-z0-9]{24,}',
     "stripe_restricted_key", "Stripe", SecretSeverity.HIGH,
     "Stripe Restricted Key detected",
     "Rotate at dashboard.stripe.com. Use environment variables."),

    (r'whsec_[A-Za-z0-9]{32,}',
     "stripe_webhook_secret", "Stripe", SecretSeverity.HIGH,
     "Stripe Webhook Signing Secret detected",
     "Rotate at dashboard.stripe.com. Store in env: STRIPE_WEBHOOK_SECRET"),

    # ── Google / GCP ──
    (r'AIza[0-9A-Za-z_\-]{35}',
     "google_api_key", "Google", SecretSeverity.HIGH,
     "Google API Key detected",
     "Restrict this key at console.cloud.google.com. Use application default credentials for GCP."),

    (r'[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com',
     "google_oauth_client", "Google", SecretSeverity.MEDIUM,
     "Google OAuth Client ID detected",
     "Client IDs are semi-public but shouldn't be hardcoded. Use env: GOOGLE_CLIENT_ID"),

    (r'ya29\.[A-Za-z0-9_\-]{50,}',
     "google_oauth_token", "Google", SecretSeverity.CRITICAL,
     "Google OAuth Access Token detected",
     "This is a short-lived token. Never commit OAuth tokens. Use service account authentication."),

    (r'"type"\s*:\s*"service_account"',
     "gcp_service_account", "GCP", SecretSeverity.CRITICAL,
     "GCP Service Account JSON Key detected",
     "Delete and rotate at console.cloud.google.com. Use Workload Identity Federation instead."),

    # ── Firebase ──
    (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
     "firebase_cloud_messaging", "Firebase", SecretSeverity.HIGH,
     "Firebase Cloud Messaging Server Key detected",
     "Rotate at console.firebase.google.com. Use FCM v1 API with service accounts."),

    # ── Azure ──
    (r'(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,}',
     "azure_storage_connection", "Azure", SecretSeverity.CRITICAL,
     "Azure Storage Connection String detected",
     "Rotate key in Azure Portal. Use Managed Identity or Azure Key Vault."),

    (r'(?i)(?:Password|pwd)\s*=\s*[^;]{8,}(?:;|$)',
     "azure_sql_connection", "Azure", SecretSeverity.HIGH,
     "Potential Azure SQL Connection String with password",
     "Use Azure AD authentication or store connection string in Key Vault."),

    # ── Twilio ──
    (r'SK[0-9a-fA-F]{32}',
     "twilio_api_key", "Twilio", SecretSeverity.HIGH,
     "Twilio API Key detected",
     "Rotate at twilio.com/console. Use env: TWILIO_API_KEY"),

    (r'AC[a-z0-9]{32}',
     "twilio_account_sid", "Twilio", SecretSeverity.MEDIUM,
     "Twilio Account SID detected",
     "SIDs are semi-public but should not be hardcoded. Use env: TWILIO_ACCOUNT_SID"),

    # ── SendGrid ──
    (r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',
     "sendgrid_api_key", "SendGrid", SecretSeverity.CRITICAL,
     "SendGrid API Key detected",
     "Rotate at app.sendgrid.com. Use env: SENDGRID_API_KEY"),

    # ── Mailgun ──
    (r'key-[0-9a-zA-Z]{32}',
     "mailgun_api_key", "Mailgun", SecretSeverity.HIGH,
     "Mailgun API Key detected",
     "Rotate at app.mailgun.com. Use env: MAILGUN_API_KEY"),

    # ── npm ──
    (r'npm_[A-Za-z0-9]{36}',
     "npm_token", "npm", SecretSeverity.CRITICAL,
     "npm Access Token detected",
     "Revoke at npmjs.com/settings/tokens. Use npm login in CI or NPM_TOKEN env var."),

    # ── PyPI ──
    (r'pypi-[A-Za-z0-9_-]{100,}',
     "pypi_token", "PyPI", SecretSeverity.CRITICAL,
     "PyPI API Token detected",
     "Revoke at pypi.org/manage/account/token/. Use trusted publishers for CI/CD."),

    # ── Discord ──
    (r'[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}',
     "discord_bot_token", "Discord", SecretSeverity.CRITICAL,
     "Discord Bot Token detected",
     "Reset at discord.com/developers. Use env: DISCORD_BOT_TOKEN"),

    (r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+',
     "discord_webhook", "Discord", SecretSeverity.MEDIUM,
     "Discord Webhook URL detected",
     "Rotate webhook in Discord channel settings. Use env: DISCORD_WEBHOOK_URL"),

    # ── Telegram ──
    (r'[0-9]{8,10}:[A-Za-z0-9_-]{35}',
     "telegram_bot_token", "Telegram", SecretSeverity.HIGH,
     "Telegram Bot Token detected",
     "Revoke via @BotFather. Use env: TELEGRAM_BOT_TOKEN"),

    # ── OpenAI ──
    (r'sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}',
     "openai_api_key_legacy", "OpenAI", SecretSeverity.CRITICAL,
     "OpenAI API Key (legacy format) detected",
     "Rotate at platform.openai.com. Use env: OPENAI_API_KEY"),

    (r'sk-proj-[A-Za-z0-9_-]{40,}',
     "openai_api_key_project", "OpenAI", SecretSeverity.CRITICAL,
     "OpenAI Project API Key detected",
     "Rotate at platform.openai.com. Use env: OPENAI_API_KEY"),

    # ── Anthropic ──
    (r'sk-ant-[A-Za-z0-9_-]{90,}',
     "anthropic_api_key", "Anthropic", SecretSeverity.CRITICAL,
     "Anthropic API Key detected",
     "Rotate at console.anthropic.com. Use env: ANTHROPIC_API_KEY"),

    # ── Supabase ──
    (r'(?i)(?:supabase_key|supabase_anon|service_role)\s*[=:]\s*["\']?(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
     "supabase_service_key", "Supabase", SecretSeverity.CRITICAL,
     "Supabase Service Role Key detected",
     "Never expose service_role key. Use SUPABASE_SERVICE_ROLE_KEY env var. Anon key is okay for frontend."),

    # ── Vercel ──
    (r'(?i)vercel_[A-Za-z0-9_]{20,}',
     "vercel_token", "Vercel", SecretSeverity.HIGH,
     "Vercel Token detected",
     "Rotate at vercel.com/account/tokens. Use VERCEL_TOKEN env var."),

    # ── Cloudflare ──
    (r'(?i)(?:cloudflare|cf)[\s_-]*(?:api[\s_-]*)?(?:key|token)\s*[=:]\s*["\']?([A-Za-z0-9_-]{37,})',
     "cloudflare_api_key", "Cloudflare", SecretSeverity.HIGH,
     "Cloudflare API Key/Token detected",
     "Rotate at dash.cloudflare.com. Use CF_API_TOKEN env var."),

    # ── JWT ──
    (r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
     "jwt_token", "JWT", SecretSeverity.MEDIUM,
     "JWT Token detected",
     "JWT tokens should not be hardcoded. Generate at runtime and store in secure session/cookie."),

    # ── Private Keys ──
    (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
     "rsa_private_key", "Cryptography", SecretSeverity.CRITICAL,
     "RSA Private Key detected",
     "NEVER commit private keys. Use environment variables or a secret manager like HashiCorp Vault."),

    (r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----',
     "ec_private_key", "Cryptography", SecretSeverity.CRITICAL,
     "EC Private Key detected",
     "NEVER commit private keys. Store in secure key management system."),

    (r'-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----',
     "dsa_private_key", "Cryptography", SecretSeverity.CRITICAL,
     "DSA Private Key detected (also: DSA is deprecated, use Ed25519)",
     "Remove key from source. Use Ed25519 keys and store securely."),

    (r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----',
     "ssh_private_key", "SSH", SecretSeverity.CRITICAL,
     "OpenSSH Private Key detected",
     "NEVER commit SSH keys. Use ssh-agent or deployment keys with minimal permissions."),

    (r'-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----',
     "pgp_private_key", "PGP", SecretSeverity.CRITICAL,
     "PGP Private Key Block detected",
     "Remove PGP private key from source. Import into keyring and protect with passphrase."),

    # ── Database URLs ──
    (r'(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s"\'<>]+:[^\s"\'<>]+@[^\s"\'<>]+',
     "database_url", "Database", SecretSeverity.CRITICAL,
     "Database Connection URL with embedded credentials detected",
     "Use env: DATABASE_URL. Store connection strings in secret manager."),

    # ── Generic Secrets (lower precision, use with entropy) ──
    (r'(?i)(?:password|passwd|pwd|secret|token|auth_key|api_key|apikey|access_key|private_key|secret_key)\s*[=:]\s*["\'][^"\']{8,}["\']',
     "generic_secret", "Generic", SecretSeverity.HIGH,
     "Hardcoded secret value detected",
     "Use environment variables or a secret manager. Never hardcode sensitive values."),

    # ── Bearer Tokens ──
    (r'(?i)(?:authorization|bearer)\s*[=:]\s*["\']?Bearer\s+[A-Za-z0-9_\-\.]{20,}',
     "bearer_token", "HTTP", SecretSeverity.HIGH,
     "Hardcoded Bearer Token detected",
     "Tokens should be loaded from environment or secret manager at runtime."),

    # ── Heroku ──
    (r'(?i)heroku[_\s-]*api[_\s-]*key\s*[=:]\s*["\']?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
     "heroku_api_key", "Heroku", SecretSeverity.HIGH,
     "Heroku API Key detected",
     "Rotate at dashboard.heroku.com. Use HEROKU_API_KEY env var."),

    # ── Datadog ──
    (r'(?i)dd[_\s-]*api[_\s-]*key\s*[=:]\s*["\']?[a-f0-9]{32}',
     "datadog_api_key", "Datadog", SecretSeverity.HIGH,
     "Datadog API Key detected",
     "Rotate at app.datadoghq.com. Use DD_API_KEY env var."),

    # ── Sentry ──
    (r'https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+',
     "sentry_dsn", "Sentry", SecretSeverity.MEDIUM,
     "Sentry DSN detected",
     "DSN is semi-public (used in frontend) but should be in env: SENTRY_DSN"),

    # ── Linear ──
    (r'lin_api_[A-Za-z0-9]{40,}',
     "linear_api_key", "Linear", SecretSeverity.HIGH,
     "Linear API Key detected",
     "Rotate at linear.app/settings. Use LINEAR_API_KEY env var."),

    # ── Shopify ──
    (r'shpat_[a-fA-F0-9]{32}',
     "shopify_access_token", "Shopify", SecretSeverity.HIGH,
     "Shopify Access Token detected",
     "Rotate in Shopify Admin. Use SHOPIFY_ACCESS_TOKEN env var."),

    (r'shpss_[a-fA-F0-9]{32}',
     "shopify_shared_secret", "Shopify", SecretSeverity.HIGH,
     "Shopify Shared Secret detected",
     "Rotate in Shopify Admin. Store in env: SHOPIFY_SHARED_SECRET"),
]


# ─────────────────────────────────────────────────────────
# FILES TO SKIP
# ─────────────────────────────────────────────────────────

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".bz2",
    ".pyc", ".pyo", ".class",
    ".lock",  # lockfiles have hashes, not secrets
}

SKIP_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Pipfile.lock", "poetry.lock", "Cargo.lock",
    "composer.lock", "Gemfile.lock", "go.sum",
}

# Lines matching these patterns are likely false positives
FALSE_POSITIVE_PATTERNS = [
    r'^\s*#',                     # Comments in config files
    r'^\s*//',                    # JS comments
    r'example\.com',              # Example domains
    r'placeholder',               # Placeholder text
    r'your[-_]?(api[-_]?key|token|secret)',  # Template placeholders
    r'<YOUR[-_]',                 # Template variables
    r'REPLACE[-_]?(ME|THIS)',     # Replace me markers
    r'xxx+',                      # Placeholder xxx
    r'test[-_]?key',              # Test keys
    r'fake[-_]?',                 # Fake values
    r'dummy',                     # Dummy values
    r'sample',                    # Sample values
    r'(?i)process\.env\.',        # Environment variable access (not a secret)
    r'(?i)os\.environ',           # Python env access
    r'(?i)os\.getenv',            # Python env access
    r'(?i)env\(\s*["\']',         # Framework env() calls
    r'(?i)config\.',              # Config references
    r'(?i)\.env\.',               # .env references
]


class SecretsDetector:
    """Advanced secrets detection engine.
    
    Uses pattern matching for known secrets (high precision) and
    Shannon entropy analysis for unknown secrets (high recall).
    """

    def __init__(self, entropy_threshold: float = 4.5, enable_entropy: bool = True):
        """Initialize detector.
        
        Args:
            entropy_threshold: Minimum Shannon entropy to flag (default 4.5)
            enable_entropy: Whether to run entropy analysis (can add noise)
        """
        self.entropy_threshold = entropy_threshold
        self.enable_entropy = enable_entropy
        self._compiled_patterns = [
            (_compile(p[0]), p[1], p[2], p[3], p[4], p[5])
            for p in KNOWN_PATTERNS
        ]
        self._fp_patterns = [_compile(p, re.IGNORECASE) for p in FALSE_POSITIVE_PATTERNS]

    def scan(self, code: str, filename: str = "unknown") -> List[SecretFinding]:
        """Scan code for secrets.
        
        Args:
            code: Source code content
            filename: Filename for context and filtering
            
        Returns:
            List of SecretFinding objects, sorted by severity
        """
        # Skip binary/irrelevant files
        if self._should_skip_file(filename):
            return []

        findings: List[SecretFinding] = []
        lines = code.splitlines()

        for line_num, line in enumerate(lines, 1):
            # Skip lines that are likely false positives
            if self._is_false_positive_line(line):
                continue

            # Strategy 1: Known service patterns
            for pattern, type_id, service, severity, message, suggestion in self._compiled_patterns:
                for match in pattern.finditer(line):
                    matched = match.group(0)
                    
                    # Additional false positive check on the matched value
                    if self._is_false_positive_value(matched, line):
                        continue

                    findings.append(SecretFinding(
                        type=type_id,
                        service=service,
                        severity=severity,
                        message=message,
                        line=line_num,
                        column=match.start() + 1,
                        matched_text=matched,
                        raw_length=len(matched),
                        file=filename,
                        suggestion=suggestion,
                        cwe_id="CWE-798",
                    ))

            # Strategy 2: Entropy-based detection for quoted strings
            if self.enable_entropy:
                entropy_findings = self._check_entropy(line, line_num, filename)
                findings.extend(entropy_findings)

        # Deduplicate findings at same location
        findings = self._deduplicate(findings)

        # Sort: critical first, then by line number
        severity_order = {
            SecretSeverity.CRITICAL: 0,
            SecretSeverity.HIGH: 1,
            SecretSeverity.MEDIUM: 2,
            SecretSeverity.LOW: 3,
            SecretSeverity.INFO: 4,
        }
        findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.line))

        return findings

    def scan_file(self, filepath: str) -> List[SecretFinding]:
        """Scan a file for secrets.
        
        Args:
            filepath: Path to file to scan
            
        Returns:
            List of SecretFinding objects
        """
        path = Path(filepath)
        if not path.exists() or not path.is_file():
            return []
        
        if path.suffix in SKIP_EXTENSIONS or path.name in SKIP_FILENAMES:
            return []

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            return []

        return self.scan(content, str(path.name))

    def scan_directory(self, directory: str, max_files: int = 500) -> Dict[str, List[SecretFinding]]:
        """Scan all files in a directory.
        
        Args:
            directory: Path to directory
            max_files: Maximum files to scan (default 500)
            
        Returns:
            Dict mapping filename to list of findings
        """
        results: Dict[str, List[SecretFinding]] = {}
        dir_path = Path(directory)
        scanned = 0

        for filepath in dir_path.rglob("*"):
            if scanned >= max_files:
                break
            if not filepath.is_file():
                continue
            if any(part.startswith(".") for part in filepath.parts):
                continue  # Skip hidden directories
            if filepath.suffix in SKIP_EXTENSIONS or filepath.name in SKIP_FILENAMES:
                continue

            findings = self.scan_file(str(filepath))
            if findings:
                results[str(filepath.relative_to(dir_path))] = findings
            scanned += 1

        return results

    # ── Entropy Analysis ──

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string.
        
        Higher entropy = more random = more likely to be a secret.
        Natural language: ~3.5-4.0
        Random hex: ~3.7-4.0  
        Base64 encoded data: ~5.0-6.0
        Truly random: ~5.5-6.0
        """
        if not text:
            return 0.0

        freq: Dict[str, int] = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        length = len(text)
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _check_entropy(self, line: str, line_num: int, filename: str) -> List[SecretFinding]:
        """Check for high-entropy strings that might be secrets."""
        findings = []

        # Find quoted strings
        quoted_pattern = _compile(r'''["']([^"']{16,})["']''')
        for match in quoted_pattern.finditer(line):
            value = match.group(1)

            # Skip if it looks like a regular string
            if " " in value and value.count(" ") > 2:
                continue  # Likely a sentence
            if value.startswith("http://") or value.startswith("https://"):
                if "@" not in value:  # URLs with @ might contain creds
                    continue

            entropy = self._shannon_entropy(value)
            if entropy >= self.entropy_threshold and len(value) >= 16:
                # Additional heuristic: check character diversity
                unique_ratio = len(set(value)) / len(value)
                if unique_ratio > 0.4:  # High character diversity
                    findings.append(SecretFinding(
                        type="high_entropy_string",
                        service="Unknown",
                        severity=SecretSeverity.MEDIUM,
                        message=f"High-entropy string detected (entropy: {entropy:.2f})",
                        line=line_num,
                        column=match.start() + 1,
                        matched_text=value,
                        raw_length=len(value),
                        file=filename,
                        suggestion="Verify this is not a secret. If it is, move to environment variables.",
                        entropy=entropy,
                    ))

        return findings

    # ── False Positive Filtering ──

    def _should_skip_file(self, filename: str) -> bool:
        """Check if file should be skipped."""
        if not filename:
            return False
        ext = Path(filename).suffix.lower()
        name = Path(filename).name
        return ext in SKIP_EXTENSIONS or name in SKIP_FILENAMES

    def _is_false_positive_line(self, line: str) -> bool:
        """Check if line is likely a false positive."""
        stripped = line.strip()
        if not stripped:
            return True

        for pattern in self._fp_patterns:
            if pattern.search(stripped):
                return True

        return False

    def _is_false_positive_value(self, value: str, line: str) -> bool:
        """Check if matched value is likely not a real secret."""
        lower = value.lower()

        # Too short to be a real secret
        if len(value) < 6:
            return True

        # All same character
        if len(set(value.replace("-", "").replace("_", ""))) <= 2:
            return True

        # Common test/placeholder values
        test_values = {
            "password", "secret", "token", "apikey", "api_key",
            "changeme", "example", "placeholder", "testtest",
            "12345678", "abcdefgh", "qwerty123",
        }
        if lower in test_values:
            return True

        # Is it in an env access pattern on the same line?
        env_patterns = [
            "os.environ", "os.getenv", "process.env",
            "env(", "getenv(", "environ.get",
            ".env.", "config[",
        ]
        lower_line = line.lower()
        for ep in env_patterns:
            if ep in lower_line:
                return True

        return False

    def _deduplicate(self, findings: List[SecretFinding]) -> List[SecretFinding]:
        """Remove duplicate findings at the same location."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.line, f.type, f.matched_text[:20] if f.matched_text else "")
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    # ── Reporting ──

    def format_report(self, findings: List[SecretFinding]) -> str:
        """Generate a formatted markdown report of findings."""
        if not findings:
            return "## 🔑 Secrets Scan Report\n\n✅ **No secrets detected!** Your code is clean.\n"

        lines = [
            "## 🔑 Secrets Scan Report",
            "",
            f"### ⚠️ Found {len(findings)} potential secret(s)",
            "",
        ]

        # Group by severity
        by_severity: Dict[SecretSeverity, List[SecretFinding]] = {}
        for f in findings:
            by_severity.setdefault(f.severity, []).append(f)

        severity_emoji = {
            SecretSeverity.CRITICAL: "🔴",
            SecretSeverity.HIGH: "🟠",
            SecretSeverity.MEDIUM: "🟡",
            SecretSeverity.LOW: "🔵",
            SecretSeverity.INFO: "⚪",
        }

        for severity in [SecretSeverity.CRITICAL, SecretSeverity.HIGH,
                         SecretSeverity.MEDIUM, SecretSeverity.LOW, SecretSeverity.INFO]:
            group = by_severity.get(severity, [])
            if not group:
                continue

            emoji = severity_emoji.get(severity, "")
            lines.append(f"### {emoji} {severity.value.upper()} ({len(group)})")
            lines.append("")

            for f in group:
                lines.append(f"- **Line {f.line}** [{f.service}] {f.message}")
                lines.append(f"  - `{f.redacted}`")
                if f.suggestion:
                    lines.append(f"  - 💡 {f.suggestion}")
                if f.entropy is not None:
                    lines.append(f"  - Entropy: {f.entropy:.2f}")
                lines.append("")

        return "\n".join(lines)

    def get_statistics(self, findings: List[SecretFinding]) -> Dict:
        """Get statistics about findings."""
        services = {}
        severities = {}
        types = {}

        for f in findings:
            services[f.service] = services.get(f.service, 0) + 1
            severities[f.severity.value] = severities.get(f.severity.value, 0) + 1
            types[f.type] = types.get(f.type, 0) + 1

        return {
            "total": len(findings),
            "by_severity": severities,
            "by_service": services,
            "by_type": types,
            "has_critical": any(f.severity == SecretSeverity.CRITICAL for f in findings),
        }
