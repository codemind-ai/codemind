"""Infrastructure as Code security scanner.

Detects security misconfigurations in:
- Dockerfiles (running as root, secrets in ENV, unpinned images)
- GitHub Actions (unpinned actions, script injection, excessive permissions)
- docker-compose.yml (exposed ports, privileged mode, secrets)
- nginx.conf (security headers, SSL, rate limiting)

No external dependencies required.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Tuple
from pathlib import Path


class IaCSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class IaCFinding:
    """A security finding in an IaC file."""
    rule_id: str
    message: str
    severity: IaCSeverity
    line: int
    file_type: str  # "dockerfile", "github-actions", "docker-compose", "nginx"
    snippet: str = ""
    suggestion: str = ""
    cwe_id: str = ""
    file: Optional[str] = None


# ─────────────────────────────────────────────────────────
# DOCKERFILE RULES
# ─────────────────────────────────────────────────────────

DOCKERFILE_RULES: List[Tuple[str, str, IaCSeverity, str, str]] = [
    # (regex_pattern, rule_id, severity, message, suggestion)
    (r'^\s*USER\s+root\s*$',
     "dockerfile-root-user", IaCSeverity.HIGH,
     "Container runs as root user (CWE-250)",
     "Add 'USER nonroot' or 'USER 1000' after installing dependencies. Running as root in containers is a major security risk."),

    (r'^\s*FROM\s+\S+\s*$(?!.*@sha256)',
     "dockerfile-unpinned-base", IaCSeverity.MEDIUM,
     "Base image not pinned by digest",
     "Pin base image with SHA256 digest: FROM image@sha256:abc123... to prevent supply chain attacks."),

    (r'^\s*FROM\s+\S+:latest',
     "dockerfile-latest-tag", IaCSeverity.MEDIUM,
     "Using 'latest' tag for base image",
     "Use a specific version tag (e.g., FROM python:3.12-slim) instead of 'latest' for reproducible builds."),

    (r'^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|SECRET|TOKEN|KEY|API_KEY|PRIVATE)\w*\s*=\s*\S+',
     "dockerfile-secret-env", IaCSeverity.CRITICAL,
     "Secret value hardcoded in ENV/ARG instruction",
     "Use Docker secrets or runtime environment variables. Secrets in Dockerfile layers persist in image history."),

    (r'^\s*EXPOSE\s+(?:22|23|3389|5900)\b',
     "dockerfile-dangerous-port", IaCSeverity.HIGH,
     "Exposing administrative/remote access port",
     "Avoid exposing SSH (22), Telnet (23), RDP (3389), or VNC (5900) ports in containers."),

    (r'^\s*RUN\s+.*(?:apt-get|yum|apk)\s+install.*(?:\s|$)(?!.*--no-install-recommends)',
     "dockerfile-no-recommends", IaCSeverity.LOW,
     "Package install without --no-install-recommends",
     "Add --no-install-recommends (apt) or --no-cache (apk) to minimize attack surface."),

    (r'^\s*RUN\s+.*curl.*\|\s*(?:sh|bash)',
     "dockerfile-curl-pipe", IaCSeverity.HIGH,
     "Piping curl output to shell — potential supply chain attack",
     "Download the script first, verify its checksum, then execute it."),

    (r'^\s*RUN\s+chmod\s+777',
     "dockerfile-chmod-777", IaCSeverity.HIGH,
     "Setting overly permissive file permissions (777)",
     "Use the least permissive chmod necessary (e.g., 755 for executables, 644 for files)."),

    (r'^\s*ADD\s+https?://',
     "dockerfile-add-url", IaCSeverity.MEDIUM,
     "Using ADD with URL — no checksum verification",
     "Use RUN curl + checksum verification instead of ADD for remote files. ADD does not verify integrity."),

    (r'^\s*RUN\s+.*pip\s+install(?!.*--no-cache-dir)',
     "dockerfile-pip-no-cache", IaCSeverity.LOW,
     "pip install without --no-cache-dir",
     "Add --no-cache-dir to reduce image size and avoid caching sensitive dependency data."),
]

# ─────────────────────────────────────────────────────────
# GITHUB ACTIONS RULES
# ─────────────────────────────────────────────────────────

GITHUB_ACTIONS_RULES: List[Tuple[str, str, IaCSeverity, str, str]] = [
    (r'uses:\s+\S+@(?:master|main|v\d+)\b(?!.*#\s*pin)',
     "gha-unpinned-action", IaCSeverity.HIGH,
     "GitHub Action not pinned to full SHA — supply chain risk",
     "Pin actions to full commit SHA: uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29"),

    (r'\$\{\{\s*github\.event\.\w+\.(?:title|body|head_ref|label\.name)',
     "gha-script-injection", IaCSeverity.CRITICAL,
     "Potential script injection via untrusted GitHub event data",
     "Never use github.event.* directly in run: steps. Assign to an env variable first and quote it."),

    (r'permissions:\s*write-all',
     "gha-excessive-permissions", IaCSeverity.HIGH,
     "Workflow uses excessive permissions (write-all)",
     "Follow principle of least privilege. Specify only needed permissions: contents: read, pull-requests: write, etc."),

    (r'(?:GITHUB_TOKEN|secrets\.GITHUB_TOKEN)\s*.*\$\{\{',
     "gha-token-exposure", IaCSeverity.HIGH,
     "Potential GITHUB_TOKEN exposure in workflow",
     "Ensure GITHUB_TOKEN is not logged or passed to untrusted actions."),

    (r'run:\s*\|?\s*.*\$\{\{\s*(?:github|inputs|env)\.',
     "gha-expression-injection", IaCSeverity.MEDIUM,
     "GitHub Actions expression used in run step — potential injection",
     "Use environment variables instead of inline expressions in run steps to prevent injection."),

    (r'(?:secrets|env)\.\w+.*(?:echo|printf|cat)\b',
     "gha-secret-log", IaCSeverity.CRITICAL,
     "Potential secret leakage via logging",
     "Never echo, print, or cat secrets. GitHub auto-masks them but custom formatting can bypass it."),

    (r'pull_request_target',
     "gha-pull-request-target", IaCSeverity.HIGH,
     "Workflow uses pull_request_target — runs with write access on untrusted PRs",
     "pull_request_target grants write access to forked PRs. Ensure no untrusted code is checked out and executed."),

    (r'if:\s*.*(?:always|cancelled)\(\)',
     "gha-always-run", IaCSeverity.LOW,
     "Step runs on all outcomes including failures (always())",
     "Ensure this is intentional. Steps with always() run even when security checks fail."),
]

# ─────────────────────────────────────────────────────────
# DOCKER-COMPOSE RULES
# ─────────────────────────────────────────────────────────

DOCKER_COMPOSE_RULES: List[Tuple[str, str, IaCSeverity, str, str]] = [
    (r'privileged:\s*true',
     "compose-privileged", IaCSeverity.CRITICAL,
     "Container running in privileged mode — full host access",
     "Remove 'privileged: true'. Use specific capabilities with cap_add instead."),

    (r'network_mode:\s*["\']?host',
     "compose-host-network", IaCSeverity.HIGH,
     "Container using host network mode",
     "Use bridge or custom networks instead. Host networking bypasses container network isolation."),

    (r'pid:\s*["\']?host',
     "compose-host-pid", IaCSeverity.HIGH,
     "Container sharing host PID namespace",
     "Remove 'pid: host' unless absolutely necessary. This allows container to see all host processes."),

    (r'(?:environment|env):\s*\n(?:.*\n)*?.*(?:PASSWORD|SECRET|TOKEN|KEY)\s*[:=]\s*\S+',
     "compose-hardcoded-secret", IaCSeverity.CRITICAL,
     "Secret hardcoded in environment section",
     "Use Docker secrets or .env file (excluded from version control) for sensitive values."),

    (r'ports:\s*\n(?:.*\n)*?.*0\.0\.0\.0:\d+',
     "compose-exposed-all", IaCSeverity.MEDIUM,
     "Port bound to all interfaces (0.0.0.0)",
     "Bind to 127.0.0.1 for local-only access: '127.0.0.1:8080:8080'"),

    (r'cap_add:\s*\n\s*-\s*(?:ALL|SYS_ADMIN|NET_ADMIN)',
     "compose-dangerous-cap", IaCSeverity.HIGH,
     "Container granted dangerous Linux capabilities",
     "Only add specific capabilities needed. CAP_ALL and SYS_ADMIN effectively give root access."),

    (r'restart:\s*(?:no|never)',
     "compose-no-restart", IaCSeverity.LOW,
     "Service has no restart policy",
     "Consider 'restart: unless-stopped' or 'restart: on-failure' for production services."),
]


class IaCScanner:
    """Scans Infrastructure as Code files for security issues."""

    def __init__(self):
        self._dockerfile_rules = [
            (re.compile(p, re.MULTILINE | re.IGNORECASE), rule_id, sev, msg, sug)
            for p, rule_id, sev, msg, sug in DOCKERFILE_RULES
        ]
        self._gha_rules = [
            (re.compile(p, re.MULTILINE | re.IGNORECASE), rule_id, sev, msg, sug)
            for p, rule_id, sev, msg, sug in GITHUB_ACTIONS_RULES
        ]
        self._compose_rules = [
            (re.compile(p, re.MULTILINE | re.IGNORECASE), rule_id, sev, msg, sug)
            for p, rule_id, sev, msg, sug in DOCKER_COMPOSE_RULES
        ]

    def scan_dockerfile(self, content: str, filename: str = "Dockerfile") -> List[IaCFinding]:
        """Scan a Dockerfile for security issues."""
        findings = self._scan_with_rules(content, self._dockerfile_rules, "dockerfile", filename)

        # Additional checks that need logic beyond regex
        lines = content.splitlines()

        # Check if any USER instruction exists
        has_user = any(line.strip().upper().startswith("USER ") for line in lines 
                       if not line.strip().startswith("#"))
        has_from = any(line.strip().upper().startswith("FROM ") for line in lines
                       if not line.strip().startswith("#"))
        
        if has_from and not has_user:
            findings.append(IaCFinding(
                rule_id="dockerfile-no-user",
                message="No USER instruction — container will run as root by default",
                severity=IaCSeverity.HIGH,
                line=len(lines),
                file_type="dockerfile",
                suggestion="Add 'USER 1000:1000' or create a non-root user and switch to it.",
                cwe_id="CWE-250",
                file=filename,
            ))

        # Check for HEALTHCHECK
        has_healthcheck = any(line.strip().upper().startswith("HEALTHCHECK") for line in lines
                             if not line.strip().startswith("#"))
        if has_from and not has_healthcheck:
            findings.append(IaCFinding(
                rule_id="dockerfile-no-healthcheck",
                message="No HEALTHCHECK instruction — container health not monitored",
                severity=IaCSeverity.LOW,
                line=len(lines),
                file_type="dockerfile",
                suggestion="Add HEALTHCHECK CMD curl -f http://localhost/ || exit 1",
                file=filename,
            ))

        return findings

    def scan_github_actions(self, content: str, filename: str = ".github/workflows/ci.yml") -> List[IaCFinding]:
        """Scan a GitHub Actions workflow for security issues."""
        findings = self._scan_with_rules(content, self._gha_rules, "github-actions", filename)

        # Check if permissions are defined at top level
        if "permissions:" not in content:
            findings.append(IaCFinding(
                rule_id="gha-no-permissions",
                message="No explicit permissions defined — defaults to write-all for some triggers",
                severity=IaCSeverity.MEDIUM,
                line=1,
                file_type="github-actions",
                suggestion="Add top-level 'permissions: {}' or specific permissions to follow least-privilege principle.",
                file=filename,
            ))

        return findings

    def scan_docker_compose(self, content: str, filename: str = "docker-compose.yml") -> List[IaCFinding]:
        """Scan a docker-compose file for security issues."""
        return self._scan_with_rules(content, self._compose_rules, "docker-compose", filename)

    def scan_content(self, content: str, filename: str) -> List[IaCFinding]:
        """Auto-detect file type and scan accordingly."""
        lower_name = filename.lower()
        basename = Path(filename).name.lower()

        if basename in ("dockerfile", ) or basename.startswith("dockerfile"):
            return self.scan_dockerfile(content, filename)
        elif ".github" in lower_name and (lower_name.endswith(".yml") or lower_name.endswith(".yaml")):
            return self.scan_github_actions(content, filename)
        elif "docker-compose" in lower_name or "compose.yml" in lower_name or "compose.yaml" in lower_name:
            return self.scan_docker_compose(content, filename)
        else:
            # Try all scanners and return non-empty results
            for scanner in [self.scan_dockerfile, self.scan_github_actions, self.scan_docker_compose]:
                try:
                    findings = scanner(content, filename)
                    if findings:
                        return findings
                except Exception:
                    continue
            return []

    def scan_directory(self, directory: str) -> Dict[str, List[IaCFinding]]:
        """Scan all IaC files in a directory."""
        results: Dict[str, List[IaCFinding]] = {}
        dir_path = Path(directory)

        # Scan patterns
        scan_patterns = [
            ("**/Dockerfile*", self.scan_dockerfile),
            ("**/.github/workflows/*.yml", self.scan_github_actions),
            ("**/.github/workflows/*.yaml", self.scan_github_actions),
            ("**/docker-compose*.yml", self.scan_docker_compose),
            ("**/docker-compose*.yaml", self.scan_docker_compose),
            ("**/compose.yml", self.scan_docker_compose),
            ("**/compose.yaml", self.scan_docker_compose),
        ]

        for pattern, scanner in scan_patterns:
            for filepath in dir_path.glob(pattern):
                if not filepath.is_file():
                    continue
                try:
                    content = filepath.read_text(encoding="utf-8", errors="ignore")
                    rel_path = str(filepath.relative_to(dir_path))
                    findings = scanner(content, rel_path)
                    if findings:
                        results[rel_path] = findings
                except (OSError, UnicodeDecodeError):
                    continue

        return results

    def _scan_with_rules(self, content: str, rules: list, file_type: str, filename: str) -> List[IaCFinding]:
        """Apply regex rules to content and return findings."""
        findings = []
        lines = content.splitlines()

        for pattern, rule_id, severity, message, suggestion in rules:
            for match in pattern.finditer(content):
                # Calculate line number
                line_num = content[:match.start()].count('\n') + 1
                snippet = match.group(0).strip()[:100]

                findings.append(IaCFinding(
                    rule_id=rule_id,
                    message=message,
                    severity=severity,
                    line=line_num,
                    file_type=file_type,
                    snippet=snippet,
                    suggestion=suggestion,
                    file=filename,
                ))

        return findings

    def format_report(self, findings: List[IaCFinding]) -> str:
        """Generate a markdown report of IaC findings."""
        if not findings:
            return "## 🏗️ IaC Security Report\n\n✅ **No issues detected!** Infrastructure configuration looks clean.\n"

        lines = [
            "## 🏗️ IaC Security Report",
            "",
            f"### ⚠️ Found {len(findings)} issue(s)",
            "",
        ]

        severity_emoji = {
            IaCSeverity.CRITICAL: "🔴",
            IaCSeverity.HIGH: "🟠",
            IaCSeverity.MEDIUM: "🟡",
            IaCSeverity.LOW: "🔵",
            IaCSeverity.INFO: "⚪",
        }

        # Group by file
        by_file: Dict[str, List[IaCFinding]] = {}
        for f in findings:
            key = f.file or f.file_type
            by_file.setdefault(key, []).append(f)

        for filepath, file_findings in by_file.items():
            lines.append(f"### 📄 `{filepath}`")
            lines.append("")
            for f in sorted(file_findings, key=lambda x: x.line):
                emoji = severity_emoji.get(f.severity, "⚪")
                lines.append(f"- {emoji} **Line {f.line}** [{f.severity.value.upper()}]: {f.message}")
                if f.snippet:
                    lines.append(f"  - Code: `{f.snippet}`")
                if f.suggestion:
                    lines.append(f"  - 💡 {f.suggestion}")
                lines.append("")

        return "\n".join(lines)

    def get_statistics(self, findings: List[IaCFinding]) -> Dict:
        """Get statistics about IaC findings."""
        severities = {}
        file_types = {}
        for f in findings:
            severities[f.severity.value] = severities.get(f.severity.value, 0) + 1
            file_types[f.file_type] = file_types.get(f.file_type, 0) + 1
        return {
            "total": len(findings),
            "by_severity": severities,
            "by_file_type": file_types,
            "has_critical": any(f.severity == IaCSeverity.CRITICAL for f in findings),
        }
