"""SARIF v2.1.0 report generator.

SARIF (Static Analysis Results Interchange Format) is the industry standard
for static analysis tools. It's supported by:
- GitHub Code Scanning (uploads directly)
- VS Code SARIF Viewer
- Azure DevOps
- SonarQube
- And many CI/CD platforms

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone


@dataclass
class SARIFFinding:
    """A finding to include in the SARIF report."""
    rule_id: str
    message: str
    severity: str           # error, warning, note
    file_path: str
    line: int
    column: int = 1
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    snippet: Optional[str] = None
    fix_description: Optional[str] = None
    fix_text: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None
    help_text: Optional[str] = None
    help_uri: Optional[str] = None
    category: str = "security"
    tags: List[str] = field(default_factory=list)


# CWE mapping for common vulnerability types
CWE_MAP = {
    "SQL_INJECTION": {"cwe": "CWE-89", "owasp": "A03:2021", "name": "SQL Injection"},
    "XSS": {"cwe": "CWE-79", "owasp": "A03:2021", "name": "Cross-Site Scripting"},
    "COMMAND_INJECTION": {"cwe": "CWE-78", "owasp": "A03:2021", "name": "OS Command Injection"},
    "PATH_TRAVERSAL": {"cwe": "CWE-22", "owasp": "A01:2021", "name": "Path Traversal"},
    "CREDENTIAL_EXPOSURE": {"cwe": "CWE-798", "owasp": "A07:2021", "name": "Hardcoded Credentials"},
    "UNSAFE_DESERIALIZATION": {"cwe": "CWE-502", "owasp": "A08:2021", "name": "Unsafe Deserialization"},
    "SSRF": {"cwe": "CWE-918", "owasp": "A10:2021", "name": "Server-Side Request Forgery"},
    "OPEN_REDIRECT": {"cwe": "CWE-601", "owasp": "A01:2021", "name": "Open Redirect"},
    "WEAK_CRYPTO": {"cwe": "CWE-327", "owasp": "A02:2021", "name": "Weak Cryptography"},
    "INSECURE_RANDOM": {"cwe": "CWE-330", "owasp": "A02:2021", "name": "Insecure Randomness"},
    "DANGEROUS_FUNCTION": {"cwe": "CWE-676", "owasp": "A03:2021", "name": "Dangerous Function"},
    "CORS_MISCONFIGURATION": {"cwe": "CWE-942", "owasp": "A05:2021", "name": "CORS Misconfiguration"},
    "LDAP_INJECTION": {"cwe": "CWE-90", "owasp": "A03:2021", "name": "LDAP Injection"},
    "REGEX_DOS": {"cwe": "CWE-1333", "owasp": "A03:2021", "name": "ReDoS"},
    "RACE_CONDITION": {"cwe": "CWE-362", "owasp": "A04:2021", "name": "Race Condition"},
    "SECURITY_HEADER": {"cwe": "CWE-1021", "owasp": "A05:2021", "name": "Security Headers"},
}

# Severity mapping
SEVERITY_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "warning": "warning",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


class SARIFGenerator:
    """Generate SARIF v2.1.0 compliant reports.
    
    Usage:
        gen = SARIFGenerator()
        gen.add_finding(SARIFFinding(...))
        sarif = gen.generate()
        json_str = gen.to_json()
    """

    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
    TOOL_NAME = "CodeMind"
    TOOL_URI = "https://codemind-ai.github.io/codemind"

    def __init__(self, tool_version: str = "2.0.0"):
        self.tool_version = tool_version
        self.findings: List[SARIFFinding] = []
        self._rules_seen: Dict[str, Dict] = {}

    def add_finding(self, finding: SARIFFinding) -> None:
        """Add a finding to the report."""
        self.findings.append(finding)
        
        # Track unique rules
        if finding.rule_id not in self._rules_seen:
            self._rules_seen[finding.rule_id] = {
                "id": finding.rule_id,
                "message": finding.message,
                "severity": finding.severity,
                "cwe_id": finding.cwe_id,
                "owasp_id": finding.owasp_id,
                "help_text": finding.help_text,
                "help_uri": finding.help_uri,
                "category": finding.category,
                "tags": finding.tags,
            }

    def add_findings(self, findings: List[SARIFFinding]) -> None:
        """Add multiple findings."""
        for f in findings:
            self.add_finding(f)

    def generate(self) -> Dict[str, Any]:
        """Generate a complete SARIF document."""
        return {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [self._generate_run()],
        }

    def _generate_run(self) -> Dict[str, Any]:
        """Generate a SARIF run object."""
        run: Dict[str, Any] = {
            "tool": self._generate_tool(),
            "results": [self._generate_result(f) for f in self.findings],
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).isoformat(),
            }],
        }

        # Add taxonomies for CWE/OWASP
        taxonomies = self._generate_taxonomies()
        if taxonomies:
            run["taxonomies"] = taxonomies

        return run

    def _generate_tool(self) -> Dict[str, Any]:
        """Generate the tool section with driver and rules."""
        rules = []
        for rule_id, rule_data in self._rules_seen.items():
            rule: Dict[str, Any] = {
                "id": rule_id,
                "shortDescription": {"text": rule_data["message"][:100]},
                "defaultConfiguration": {
                    "level": SEVERITY_TO_SARIF.get(rule_data["severity"], "warning"),
                },
                "properties": {
                    "tags": rule_data.get("tags", []),
                    "category": rule_data.get("category", "security"),
                },
            }

            # Add help text
            if rule_data.get("help_text"):
                rule["help"] = {"text": rule_data["help_text"]}
            
            if rule_data.get("help_uri"):
                rule["helpUri"] = rule_data["help_uri"]

            # Add CWE/OWASP relationships
            relationships = []
            if rule_data.get("cwe_id"):
                relationships.append({
                    "target": {
                        "id": rule_data["cwe_id"],
                        "toolComponent": {"name": "CWE"},
                    },
                    "kinds": ["superset"],
                })
            if relationships:
                rule["relationships"] = relationships

            rules.append(rule)

        return {
            "driver": {
                "name": self.TOOL_NAME,
                "version": self.tool_version,
                "informationUri": self.TOOL_URI,
                "rules": rules,
                "semanticVersion": self.tool_version,
            }
        }

    def _generate_result(self, finding: SARIFFinding) -> Dict[str, Any]:
        """Generate a SARIF result object for a finding."""
        result: Dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": SEVERITY_TO_SARIF.get(finding.severity, "warning"),
            "message": {"text": finding.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file_path.replace("\\", "/"),
                    },
                    "region": self._generate_region(finding),
                }
            }],
        }

        # Add code snippet
        if finding.snippet:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": finding.snippet,
            }

        # Add fix suggestion
        if finding.fix_text:
            result["fixes"] = [{
                "description": {
                    "text": finding.fix_description or "Apply suggested fix",
                },
                "artifactChanges": [{
                    "artifactLocation": {
                        "uri": finding.file_path.replace("\\", "/"),
                    },
                    "replacements": [{
                        "deletedRegion": self._generate_region(finding),
                        "insertedContent": {"text": finding.fix_text},
                    }],
                }],
            }]

        # Add CWE/OWASP properties
        properties: Dict[str, Any] = {}
        if finding.cwe_id:
            properties["cwe"] = finding.cwe_id
        if finding.owasp_id:
            properties["owasp"] = finding.owasp_id
        if finding.category:
            properties["category"] = finding.category
        if properties:
            result["properties"] = properties

        return result

    def _generate_region(self, finding: SARIFFinding) -> Dict[str, int]:
        """Generate a SARIF region object."""
        region: Dict[str, int] = {
            "startLine": finding.line,
            "startColumn": finding.column,
        }
        if finding.end_line:
            region["endLine"] = finding.end_line
        if finding.end_column:
            region["endColumn"] = finding.end_column
        return region

    def _generate_taxonomies(self) -> List[Dict[str, Any]]:
        """Generate CWE taxonomy reference."""
        cwe_ids = set()
        for f in self.findings:
            if f.cwe_id:
                cwe_ids.add(f.cwe_id)

        if not cwe_ids:
            return []

        taxa = []
        for cwe_id in sorted(cwe_ids):
            taxa.append({
                "id": cwe_id,
                "shortDescription": {"text": cwe_id},
            })

        return [{
            "name": "CWE",
            "version": "4.13",
            "informationUri": "https://cwe.mitre.org/",
            "taxa": taxa,
        }]

    # ── Conversion helpers ──

    def to_json(self, indent: int = 2) -> str:
        """Generate SARIF as JSON string."""
        return json.dumps(self.generate(), indent=indent, ensure_ascii=False)

    def to_file(self, filepath: str) -> None:
        """Write SARIF to a file."""
        from pathlib import Path
        Path(filepath).write_text(self.to_json(), encoding="utf-8")

    # ── Conversion from Guardian findings ──

    @classmethod
    def from_guard_issues(cls, issues: list, filename: str = "unknown",
                          tool_version: str = "2.0.0") -> "SARIFGenerator":
        """Create SARIF from GuardIssue objects.
        
        Args:
            issues: List of GuardIssue objects from Guardian
            filename: Source file path
            tool_version: Tool version string
            
        Returns:
            Populated SARIFGenerator
        """
        gen = cls(tool_version=tool_version)

        for issue in issues:
            vuln_type = getattr(issue, "vulnerability_type", None) or "OTHER"
            cwe_info = CWE_MAP.get(vuln_type, {})

            finding = SARIFFinding(
                rule_id=f"codemind/{vuln_type.lower().replace(' ', '-')}",
                message=issue.message,
                severity=issue.severity.value if hasattr(issue.severity, "value") else str(issue.severity),
                file_path=issue.file or filename,
                line=issue.line or 1,
                snippet=issue.code_snippet,
                fix_description=issue.suggestion,
                cwe_id=cwe_info.get("cwe"),
                owasp_id=cwe_info.get("owasp"),
                help_text=issue.explanation or issue.suggestion,
                category="security" if hasattr(issue, "type") and str(issue.type) == "GuardType.SECURITY" else "quality",
                tags=[vuln_type] if vuln_type != "OTHER" else [],
            )
            gen.add_finding(finding)

        return gen

    @classmethod
    def from_secret_findings(cls, findings: list, tool_version: str = "2.0.0") -> "SARIFGenerator":
        """Create SARIF from SecretFinding objects."""
        gen = cls(tool_version=tool_version)

        for sf in findings:
            finding = SARIFFinding(
                rule_id=f"codemind/secrets/{sf.type}",
                message=sf.message,
                severity=sf.severity.value if hasattr(sf.severity, "value") else str(sf.severity),
                file_path=sf.file or "unknown",
                line=sf.line,
                column=sf.column,
                snippet=sf.redacted if hasattr(sf, "redacted") else sf.matched_text,
                fix_description=sf.suggestion,
                cwe_id=sf.cwe_id,
                category="security",
                tags=["secrets", sf.service],
            )
            gen.add_finding(finding)

        return gen
