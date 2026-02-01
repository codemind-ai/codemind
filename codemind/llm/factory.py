"""LLM provider factory."""

from typing import Optional
from .base import BaseLLMProvider
from .openai import OpenAIProvider
from .ollama import OllamaProvider


def get_llm_provider(
    provider_type: str = "openai",
    model: str = "gpt-4",
    api_key: Optional[str] = None,
    base_url: Optional[str] = None
) -> BaseLLMProvider:
    """Get the appropriate LLM provider."""
    
    provider_type = provider_type.lower()
    
    if provider_type == "openai":
        return OpenAIProvider(model=model, api_key=api_key, base_url=base_url)
    elif provider_type == "ollama":
        return OllamaProvider(model=model, host=base_url or "http://localhost:11434")
    else:
        raise ValueError(f"Unsupported LLM provider: {provider_type}")
