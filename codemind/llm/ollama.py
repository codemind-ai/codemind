"""Ollama LLM provider."""

import json
import requests
from typing import Optional
from .base import BaseLLMProvider, LLMResponse


class OllamaProvider(BaseLLMProvider):
    """Provider for local Ollama instances."""
    
    def __init__(self, model: str = "codellama", host: str = "http://localhost:11434"):
        self.model = model
        self.host = host
    
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> LLMResponse:
        """Generate content using Ollama API."""
        url = f"{self.host}/api/generate"
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        
        if system_prompt:
            payload["system"] = system_prompt
            
        try:
            response = requests.post(url, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            
            return LLMResponse(
                content=data.get("response", ""),
                model=self.model,
                usage={
                    "total_duration": data.get("total_duration"),
                    "load_duration": data.get("load_duration"),
                    "eval_count": data.get("eval_count"),
                }
            )
        except Exception as e:
            raise RuntimeError(f"Ollama generation failed: {e}")
