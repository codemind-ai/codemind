"""CodeMind Secrets Detection Engine.

Advanced secrets detection using pattern matching + Shannon entropy analysis.
Detects 30+ types of API keys, tokens, and credentials.
"""

from .detector import SecretsDetector, SecretFinding, SecretSeverity

__all__ = ["SecretsDetector", "SecretFinding", "SecretSeverity"]
