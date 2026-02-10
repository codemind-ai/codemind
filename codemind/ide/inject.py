"""IDE prompt injection module.

Handles copying prompts to clipboard for use in IDE AI chats.
"""

import pyperclip
from typing import Optional, Any
from dataclasses import dataclass
from enum import Enum


class InjectionResult(Enum):
    """Result of injection attempt."""
    SUCCESS = "success"
    CLIPBOARD_COPY = "clipboard_copy"
    FAILED = "failed"


@dataclass
class InjectionReport:
    """Report from a clipboard/injection operation."""
    result: InjectionResult
    message: str = ""
    prompt_in_clipboard: bool = False


def inject_prompt(
    prompt: str,
    target_ide: Optional[Any] = None,
    auto_submit: bool = False
) -> InjectionReport:
    """
    Copy a prompt to the clipboard.
    
    This function replaces the previous automated UI injection logic
    to provide a more reliable and less intrusive user experience.
    
    Args:
        prompt: The prompt text to copy
        target_ide: Ignored (legacy parameter)
        auto_submit: Ignored (legacy parameter)
    
    Returns:
        InjectionReport with the result
    """
    try:
        pyperclip.copy(prompt)
        return InjectionReport(
            result=InjectionResult.SUCCESS,
            message="Prompt copied to clipboard. Paste it into your IDE AI chat.",
            prompt_in_clipboard=True
        )
    except Exception as e:
        return InjectionReport(
            result=InjectionResult.FAILED,
            message=f"Failed to copy to clipboard: {str(e)}",
            prompt_in_clipboard=False
        )


def copy_to_clipboard(prompt: str) -> bool:
    """Simple clipboard copy utility."""
    try:
        pyperclip.copy(prompt)
        return True
    except Exception:
        return False
