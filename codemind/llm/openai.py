"""OpenAI-compatible LLM provider (OpenAI, Claude, etc.)."""

import os
from typing import Optional
from .base import BaseLLMProvider, LLMResponse


class OpenAIProvider(BaseLLMProvider):
    """Provider for OpenAI-compatible APIs."""
    
    def __init__(self, model: str = "gpt-4", api_key: Optional[str] = None, base_url: Optional[str] = None):
        self.model = model
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.base_url = base_url or "https://api.openai.com/v1"
        
        if not self.api_key:
            raise ValueError("API key must be provided or set in OPENAI_API_KEY environment variable.")
    
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> LLMResponse:
        """Generate content using OpenAI API."""
        import requests
        
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.1,  # Low temperature for stable reviews
        }
        
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=60)
            response.raise_for_status()
            data = response.json()
            
            content = data["choices"][0]["message"]["content"]
            usage = data.get("usage", {})
            
            return LLMResponse(
                content=content,
                model=self.model,
                usage=usage
            )
        except Exception as e:
            raise RuntimeError(f"OpenAI generation failed: {e}")
