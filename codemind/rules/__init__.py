"""Rules module initialization."""

from .engine import (
    RuleEngine,
    CustomRule,
    RuleMatch,
)

from .presets import (
    SECURITY_STRICT,
    PYTHON_BEST_PRACTICES,
    JAVASCRIPT_BEST_PRACTICES,
    MINIMAL,
    get_preset,
)

__all__ = [
    "RuleEngine",
    "CustomRule",
    "RuleMatch",
    "SECURITY_STRICT",
    "PYTHON_BEST_PRACTICES", 
    "JAVASCRIPT_BEST_PRACTICES",
    "MINIMAL",
    "get_preset",
]
