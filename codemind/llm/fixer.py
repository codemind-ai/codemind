"""Logic for generating automated code fixes."""

import re
from typing import Optional
from .base import BaseLLMProvider

FIX_PROMPT_TEMPLATE = """You are an expert developer. Fix the following issue in the provided code.
Return ONLY the complete fixed code for the file. No explanations, no markdown blocks, just the raw code.

---
FILE: {file_path}
ISSUE: {issue_description}
---

CURRENT CODE:
{file_content}

---
FIXED CODE:"""

class CodeFixer:
    """Generates fixes for code issues."""
    
    def __init__(self, llm: BaseLLMProvider):
        self.llm = llm
    
    def generate_fix(self, file_path: str, file_content: str, issue_description: str) -> str:
        """Generate fixed code for a file."""
        prompt = FIX_PROMPT_TEMPLATE.format(
            file_path=file_path,
            file_content=file_content,
            issue_description=issue_description
        )
        
        response = self.llm.generate(prompt)
        fixed_code = response.content.strip()
        
        # Robust extraction of code blocks
        # 1. Try to find the first and last triple backticks
        code_match = re.search(r"```(?:\w+)?\n?(.*?)```", fixed_code, re.DOTALL)
        if code_match:
            fixed_code = code_match.group(1).strip()
        else:
            # 2. Fallback: if no backticks, just use the trimmed response
            fixed_code = fixed_code.strip()
            
        return fixed_code
