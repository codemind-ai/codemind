"""CodeMind Software Composition Analysis (SCA).

Scans project dependencies for known vulnerabilities using OSV.dev API.
"""

from .scanner import DependencyScanner, SCAReport, VulnerableDependency

__all__ = ["DependencyScanner", "SCAReport", "VulnerableDependency"]
