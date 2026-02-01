"""LLM provider base class."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class LLMResponse:
    """Standard response from an LLM."""
    content: str
    model: str
    usage: Optional[dict] = None


class BaseLLMProvider(ABC):
    """Base class for all LLM providers."""
    
    @abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> LLMResponse:
        """Generate content from a prompt."""
        pass
