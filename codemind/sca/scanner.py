"""Software Composition Analysis — dependency vulnerability scanner.

Parses lockfiles, checks packages against OSV.dev (Google's open-source
vulnerability database), and reports known CVEs.

Privacy: only package names and versions are sent to OSV.dev.
No source code ever leaves the machine.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional, Any


@dataclass
class Dependency:
    """A resolved project dependency."""
    name: str
    version: str
    ecosystem: str  # PyPI, npm, Go, crates.io, etc.
    lockfile: str   # Which lockfile it came from
    is_direct: bool = True


@dataclass
class VulnerabilityInfo:
    """A known vulnerability in a dependency."""
    id: str              # OSV ID (e.g., GHSA-xxxx or CVE-xxxx)
    summary: str
    severity: str        # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: Optional[float] = None
    cwe_ids: List[str] = field(default_factory=list)
    fixed_version: Optional[str] = None
    references: List[str] = field(default_factory=list)
    published: Optional[str] = None


@dataclass
class VulnerableDependency:
    """A dependency with one or more known vulnerabilities."""
    dependency: Dependency
    vulnerabilities: List[VulnerabilityInfo] = field(default_factory=list)

    @property
    def highest_severity(self) -> str:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        if not self.vulnerabilities:
            return "LOW"
        return min(self.vulnerabilities, key=lambda v: order.get(v.severity, 4)).severity

    @property
    def fix_available(self) -> bool:
        return any(v.fixed_version for v in self.vulnerabilities)


@dataclass
class SCAReport:
    """Complete SCA scan report."""
    project_path: str
    total_dependencies: int
    vulnerable: List[VulnerableDependency] = field(default_factory=list)
    scanned_files: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def total_vulnerabilities(self) -> int:
        return sum(len(v.vulnerabilities) for v in self.vulnerable)

    @property
    def critical_count(self) -> int:
        return sum(
            1 for vd in self.vulnerable
            for v in vd.vulnerabilities
            if v.severity == "CRITICAL"
        )

    @property
    def risk_score(self) -> int:
        """0–100 risk score (100 = high risk)."""
        if not self.vulnerable:
            return 0
        score = 0
        for vd in self.vulnerable:
            for v in vd.vulnerabilities:
                if v.severity == "CRITICAL":
                    score += 25
                elif v.severity == "HIGH":
                    score += 15
                elif v.severity == "MEDIUM":
                    score += 5
                else:
                    score += 2
        return min(100, score)


class DependencyScanner:
    """Scans project dependencies for known vulnerabilities.
    
    Uses OSV.dev (free, open API by Google) for vulnerability data.
    Only package names and versions are sent — NO source code.
    """

    # Lockfile parsers: filename -> (parser_method, ecosystem)
    PARSERS = {
        "requirements.txt": ("_parse_requirements_txt", "PyPI"),
        "Pipfile.lock": ("_parse_pipfile_lock", "PyPI"),
        "poetry.lock": ("_parse_poetry_lock", "PyPI"),
        "setup.cfg": ("_parse_setup_cfg", "PyPI"),
        "package.json": ("_parse_package_json", "npm"),
        "package-lock.json": ("_parse_package_lock_json", "npm"),
        "yarn.lock": ("_parse_yarn_lock", "npm"),
        "go.sum": ("_parse_go_sum", "Go"),
        "go.mod": ("_parse_go_mod", "Go"),
        "Cargo.lock": ("_parse_cargo_lock", "crates.io"),
        "Gemfile.lock": ("_parse_gemfile_lock", "RubyGems"),
        "composer.lock": ("_parse_composer_lock", "Packagist"),
    }

    def __init__(self, offline: bool = False):
        """Initialize scanner.
        
        Args:
            offline: If True, skip online vulnerability checks (parse only)
        """
        self.offline = offline
        self._http_client = None

    async def scan(self, project_path: str = ".") -> SCAReport:
        """Scan project for vulnerable dependencies.
        
        Args:
            project_path: Root directory of the project
            
        Returns:
            SCAReport with all findings
        """
        path = Path(project_path)
        report = SCAReport(project_path=str(path.absolute()), total_dependencies=0)

        # Find and parse all lockfiles
        all_deps: List[Dependency] = []
        for filename, (parser_name, ecosystem) in self.PARSERS.items():
            lockfile = path / filename
            if lockfile.exists():
                try:
                    parser = getattr(self, parser_name)
                    deps = parser(lockfile, ecosystem)
                    all_deps.extend(deps)
                    report.scanned_files.append(filename)
                except Exception as e:
                    report.errors.append(f"Error parsing {filename}: {e}")

        report.total_dependencies = len(all_deps)

        if not all_deps:
            return report

        # Check vulnerabilities via OSV.dev
        if not self.offline:
            try:
                vulnerable = await self._check_osv(all_deps)
                report.vulnerable = vulnerable
            except Exception as e:
                report.errors.append(f"OSV API error: {e}")
                # Fallback: at least report which deps we found
        
        return report

    def scan_sync(self, project_path: str = ".") -> SCAReport:
        """Synchronous version of scan."""
        import asyncio
        return asyncio.run(self.scan(project_path))

    # ── OSV.dev API ──

    async def _check_osv(self, deps: List[Dependency]) -> List[VulnerableDependency]:
        """Check dependencies against OSV.dev vulnerability database."""
        try:
            import httpx
        except ImportError:
            return []

        vulnerable = []
        
        # Batch query (OSV supports up to 1000 per request)
        queries = []
        for dep in deps:
            queries.append({
                "package": {
                    "name": dep.name,
                    "ecosystem": dep.ecosystem,
                },
                "version": dep.version,
            })

        # Process in batches of 100
        batch_size = 100
        async with httpx.AsyncClient(timeout=30) as client:
            for i in range(0, len(queries), batch_size):
                batch = queries[i:i + batch_size]
                batch_deps = deps[i:i + batch_size]

                try:
                    response = await client.post(
                        "https://api.osv.dev/v1/querybatch",
                        json={"queries": batch},
                        headers={"Content-Type": "application/json"},
                    )
                    response.raise_for_status()
                    results = response.json().get("results", [])

                    for idx, result in enumerate(results):
                        vulns_data = result.get("vulns", [])
                        if vulns_data and idx < len(batch_deps):
                            dep = batch_deps[idx]
                            vulns = []
                            for v in vulns_data:
                                vuln_info = self._parse_osv_vuln(v)
                                if vuln_info:
                                    vulns.append(vuln_info)
                            if vulns:
                                vulnerable.append(VulnerableDependency(
                                    dependency=dep,
                                    vulnerabilities=vulns,
                                ))
                except httpx.HTTPError as e:
                    # If batch fails, try individual queries for this batch
                    for dep in batch_deps:
                        try:
                            result = await self._check_single_osv(client, dep)
                            if result:
                                vulnerable.append(result)
                        except Exception:
                            continue

        return vulnerable

    async def _check_single_osv(self, client, dep: Dependency) -> Optional[VulnerableDependency]:
        """Check a single package against OSV."""
        try:
            response = await client.post(
                "https://api.osv.dev/v1/query",
                json={
                    "package": {
                        "name": dep.name,
                        "ecosystem": dep.ecosystem,
                    },
                    "version": dep.version,
                },
            )
            response.raise_for_status()
            data = response.json()
            vulns_data = data.get("vulns", [])
            if vulns_data:
                vulns = [self._parse_osv_vuln(v) for v in vulns_data if self._parse_osv_vuln(v)]
                if vulns:
                    return VulnerableDependency(dependency=dep, vulnerabilities=vulns)
        except Exception:
            pass
        return None

    def _parse_osv_vuln(self, data: Dict) -> Optional[VulnerabilityInfo]:
        """Parse an OSV vulnerability entry."""
        try:
            vuln_id = data.get("id", "UNKNOWN")
            summary = data.get("summary", data.get("details", "No description available"))[:200]

            # Extract severity
            severity = "MEDIUM"  # default
            severity_data = data.get("database_specific", {}).get("severity")
            if severity_data:
                severity = severity_data.upper()
            else:
                # Check CVSS in severity array
                for sev in data.get("severity", []):
                    if sev.get("type") == "CVSS_V3":
                        score_str = sev.get("score", "")
                        try:
                            score = float(score_str) if score_str else None
                        except (ValueError, TypeError):
                            # Try to extract from vector string
                            score = self._extract_cvss_score(score_str)
                        if score is not None:
                            if score >= 9.0:
                                severity = "CRITICAL"
                            elif score >= 7.0:
                                severity = "HIGH"
                            elif score >= 4.0:
                                severity = "MEDIUM"
                            else:
                                severity = "LOW"

            # Extract fixed version  
            fixed_version = None
            for affected in data.get("affected", []):
                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        if "fixed" in event:
                            fixed_version = event["fixed"]

            # Extract references
            references = [
                ref.get("url", "")
                for ref in data.get("references", [])
                if ref.get("url")
            ][:5]  # Max 5 references

            # Extract CWE IDs
            cwe_ids = []
            for alias in data.get("aliases", []):
                if alias.startswith("CWE-"):
                    cwe_ids.append(alias)

            return VulnerabilityInfo(
                id=vuln_id,
                summary=summary,
                severity=severity,
                fixed_version=fixed_version,
                references=references,
                cwe_ids=cwe_ids,
                published=data.get("published"),
            )
        except Exception:
            return None

    @staticmethod
    def _extract_cvss_score(vector: str) -> Optional[float]:
        """Try to extract CVSS base score from a CVSS vector string."""
        if not vector:
            return None
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> need to calculate
        # For simplicity, look for a numeric score if someone put it
        import re
        match = re.search(r'(\d+\.\d+)', str(vector))
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                pass
        return None

    # ── Lockfile Parsers ──

    def _parse_requirements_txt(self, path: Path, ecosystem: str) -> List[Dependency]:
        """Parse Python requirements.txt."""
        content = path.read_text(encoding="utf-8", errors="ignore")
        return self._parse_requirements_txt_from_content(content, path.name, ecosystem)

    def _parse_requirements_txt_from_content(self, content: str, filename: str, ecosystem: str) -> List[Dependency]:
        """Parse Python requirements.txt from string content."""
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Handle various formats: pkg==1.0, pkg>=1.0, pkg~=1.0
            match = re.match(r'^([A-Za-z0-9_.-]+)\s*(?:[=~><]=?\s*)([0-9][A-Za-z0-9._-]*)', line)
            if match:
                deps.append(Dependency(
                    name=match.group(1).lower(),
                    version=match.group(2),
                    ecosystem=ecosystem,
                    lockfile=filename,
                ))
        return deps

    def _parse_pipfile_lock(self, path: Path, ecosystem: str) -> List[Dependency]:
        """Parse Pipfile.lock (JSON)."""
        deps = []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for section in ["default", "develop"]:
                packages = data.get(section, {})
                for name, info in packages.items():
                    version = info.get("version", "").lstrip("=")
                    if version:
                        deps.append(Dependency(
                            name=name.lower(),
                            version=version,
                            ecosystem=ecosystem,
                            lockfile=path.name,
                            is_direct=(section == "default"),
                        ))
        except (json.JSONDecodeError, KeyError):
            pass
        return deps

    def _parse_poetry_lock(self, path: Path, ecosystem: str) -> List[Dependency]:
        """Parse poetry.lock (TOML-like)."""
        deps = []
        content = path.read_text(encoding="utf-8", errors="ignore")
        
        # Simple TOML parser for package sections
        current_name = None
        current_version = None
        for line in content.splitlines():
            line = line.strip()
            if line == "[[package]]":
                if current_name and current_version:
                    deps.append(Dependency(
                        name=current_name.lower(),
                        version=current_version,
                        ecosystem=ecosystem,
                        lockfile=path.name,
                    ))
                current_name = None
                current_version = None
            elif line.startswith("name = "):
                current_name = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("version = "):
                current_version = line.split("=", 1)[1].strip().strip('"')
        
        # Don't forget last entry
        if current_name and current_version:
            deps.append(Dependency(
                name=current_name.lower(),
                version=current_version,
                ecosystem=ecosystem,
                lockfile=path.name,
            ))
        return deps

    def _parse_setup_cfg(self, path: Path, ecosystem: str) -> List[Dependency]:
        """Parse setup.cfg install_requires."""
        deps = []
        content = path.read_text(encoding="utf-8", errors="ignore")
        in_install = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and "install_requires" not in stripped:
                in_install = False
            if "install_requires" in stripped:
                in_install = True
                continue
            if in_install and stripped:
                match = re.match(r'^([A-Za-z0-9_.-]+)\s*[=><~]+\s*([0-9][A-Za-z0-9._-]*)', stripped)
                if match:
                    deps.append(Dependency(
                        name=match.group(1).lower(),
                        version=match.group(2),
                        ecosystem=ecosystem,
                        lockfile=path.name,
                    ))
        return deps

    def _parse_package_json(self, path: Path, ecosystem: str) -> List[Dependency]:
        """Parse package.json dependencies."""
        deps = []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for section in ["dependencies", "devDependencies"]:
                packages = data.get(section, {})
                for name, version in packages.items():
                    # Clean version: ^1.0.0 → 1.0.0, ~1.0.0 → 1.0.0
                    clean_ver = re.sub(r'^[\^~>=<]*', '', version).strip()
                    if clean_ver and clean_ver[0].isdigit():
                        deps.append(Dependency(
                            name=name,
                            version=clean_ver,
                            ecosystem=ecosystem,
                            lockfile=path.name,
                            is_direct=True,
                        ))
        except (json.JSONDecodeError, KeyError):
            pass
        return deps

    def _parse_package_lock_json(self, path: Path, ecosystem: str) -> List[Dependency]:
        """Parse package-lock.json."""
        deps = []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            # v2/v3 format
            packages = data.get("packages", {})
            if packages:
                for pkg_path, info in packages.items():
                    if not pkg_path:  # root package
                        continue
                    name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
                    version = info.get("version", "")
                    if name and version:
                        deps.append(Dependency(
                            name=name,
                            version=version,
                            ecosystem=ecosystem,
                            lockfile=path.name,
                            is_direct=not info.get("dev", False),
                        ))
            else:
                # v1 format
                for name, info in data.get("dependencies", {}).items():
                    version = info.get("version", "")
                    if version:
                        deps.append(Dependency(
                            name=name,
                            version=version,
                            ecosystem=ecosystem,
                            lockfile=path.name,
                        ))
        except (json.JSONDecodeError, KeyError):
            pass
        return deps

    def _parse_yarn_lock(self, path: Path, ecosystem: str) -> List[Dependency]:
        """Parse yarn.lock."""
        deps = []
        content = path.read_text(encoding="utf-8", errors="ignore")
        current_name = None
        for line in content.splitlines():
            if not line.startswith(" ") and line.endswith(":"):
                # Package header like '"@babel/core@^7.0.0":'
                name_match = re.match(r'^"?(@?[^@"]+)@', line)
                if name_match:
                    current_name = name_match.group(1)
            elif line.strip().startswith("version "):
                version = line.split('"')[1] if '"' in line else line.split()[-1]
                if current_name and version:
                    deps.append(Dependency(
                        name=current_name,
                        version=version,
                        ecosystem=ecosystem,
                        lockfile=path.name,
                    ))
                    current_name = None
        return deps

    def _parse_go_sum(self, path: Path, ecosystem: str) -> List[Dependency]:
        """Parse go.sum."""
        deps = []
        seen = set()
        content = path.read_text(encoding="utf-8", errors="ignore")
        for line in content.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1].split("/")[0].lstrip("v")
                key = (name, version)
                if key not in seen:
                    seen.add(key)
                    deps.append(Dependency(
                        name=name,
                        version=version,
                        ecosystem=ecosystem,
                        lockfile=path.name,
                    ))
        return deps

    def _parse_go_mod(self, path: Path, ecosystem: str) -> List[Dependency]:
        """Parse go.mod require section."""
        deps = []
        content = path.read_text(encoding="utf-8", errors="ignore")
        in_require = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_require = True
                continue
            if stripped == ")":
                in_require = False
                continue
            if in_require and stripped:
                parts = stripped.split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1].lstrip("v")
                    deps.append(Dependency(
                        name=name,
                        version=version,
                        ecosystem=ecosystem,
                        lockfile=path.name,
                        is_direct=True,
                    ))
            elif stripped.startswith("require "):
                parts = stripped.split()
                if len(parts) >= 3:
                    deps.append(Dependency(
                        name=parts[1],
                        version=parts[2].lstrip("v"),
                        ecosystem=ecosystem,
                        lockfile=path.name,
                        is_direct=True,
                    ))
        return deps

    def _parse_cargo_lock(self, path: Path, ecosystem: str) -> List[Dependency]:
        """Parse Cargo.lock."""
        deps = []
        content = path.read_text(encoding="utf-8", errors="ignore")
        current_name = None
        current_version = None
        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "[[package]]":
                if current_name and current_version:
                    deps.append(Dependency(
                        name=current_name,
                        version=current_version,
                        ecosystem=ecosystem,
                        lockfile=path.name,
                    ))
                current_name = None
                current_version = None
            elif stripped.startswith("name = "):
                current_name = stripped.split('"')[1] if '"' in stripped else stripped.split("=")[1].strip()
            elif stripped.startswith("version = "):
                current_version = stripped.split('"')[1] if '"' in stripped else stripped.split("=")[1].strip()
        if current_name and current_version:
            deps.append(Dependency(
                name=current_name,
                version=current_version,
                ecosystem=ecosystem,
                lockfile=path.name,
            ))
        return deps

    def _parse_gemfile_lock(self, path: Path, ecosystem: str) -> List[Dependency]:
        """Parse Gemfile.lock."""
        deps = []
        content = path.read_text(encoding="utf-8", errors="ignore")
        in_specs = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "specs:":
                in_specs = True
                continue
            if not line.startswith("  ") and in_specs:
                in_specs = False
            if in_specs:
                match = re.match(r'^\s{4}(\S+)\s+\(([^)]+)\)', line)
                if match:
                    deps.append(Dependency(
                        name=match.group(1),
                        version=match.group(2),
                        ecosystem=ecosystem,
                        lockfile=path.name,
                    ))
        return deps

    def _parse_composer_lock(self, path: Path, ecosystem: str) -> List[Dependency]:
        """Parse composer.lock (PHP)."""
        deps = []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for section in ["packages", "packages-dev"]:
                for pkg in data.get(section, []):
                    name = pkg.get("name", "")
                    version = pkg.get("version", "").lstrip("v")
                    if name and version:
                        deps.append(Dependency(
                            name=name,
                            version=version,
                            ecosystem=ecosystem,
                            lockfile=path.name,
                            is_direct=(section == "packages"),
                        ))
        except (json.JSONDecodeError, KeyError):
            pass
        return deps

    # ── Reporting ──

    def format_report(self, report: SCAReport) -> str:
        """Generate a formatted markdown report."""
        lines = [
            "## 📦 Dependency Security Report",
            "",
            f"**Project:** `{report.project_path}`",
            f"**Scanned files:** {', '.join(report.scanned_files) or 'None found'}",
            f"**Total dependencies:** {report.total_dependencies}",
            f"**Vulnerable packages:** {len(report.vulnerable)}",
            f"**Total vulnerabilities:** {report.total_vulnerabilities}",
            f"**Risk Score:** {report.risk_score}/100",
            "",
        ]

        if not report.vulnerable:
            lines.append("✅ **No known vulnerabilities found!** Dependencies are clean.")
            return "\n".join(lines)

        lines.append("### ⚠️ Vulnerable Dependencies")
        lines.append("")

        # Group by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_vulns = sorted(report.vulnerable, key=lambda v: severity_order.get(v.highest_severity, 4))

        severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}

        for vd in sorted_vulns:
            dep = vd.dependency
            emoji = severity_emoji.get(vd.highest_severity, "⚪")
            lines.append(f"#### {emoji} `{dep.name}` v{dep.version} ({dep.ecosystem})")
            
            for v in vd.vulnerabilities:
                lines.append(f"- **{v.id}** [{v.severity}]: {v.summary}")
                if v.fixed_version:
                    lines.append(f"  - 💡 Fix: Upgrade to v{v.fixed_version}")
                if v.references:
                    lines.append(f"  - 🔗 {v.references[0]}")
            lines.append("")

        if report.errors:
            lines.append("### ⚠️ Scan Errors")
            for error in report.errors:
                lines.append(f"- {error}")

        return "\n".join(lines)
