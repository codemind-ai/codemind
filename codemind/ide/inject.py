"""IDE prompt injection module.

Auto-injects review prompts into IDE AI chat windows.
"""

import sys
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import pyperclip

from .detect import DetectedIDE, IDEType, detect_preferred_ide


class InjectionResult(Enum):
    """Result of injection attempt."""
    SUCCESS = "success"
    FALLBACK_CLIPBOARD = "fallback_clipboard"
    NO_IDE_FOUND = "no_ide_found"
    INJECTION_FAILED = "injection_failed"


@dataclass
class InjectionReport:
    """Report from an injection attempt."""
    result: InjectionResult
    ide: Optional[DetectedIDE] = None
    message: str = ""
    prompt_in_clipboard: bool = False


class PromptInjector:
    """Injects prompts into IDE AI chat windows."""
    
    # Delays for UI automation (in seconds)
    FOCUS_DELAY = 0.3
    SHORTCUT_DELAY = 0.5
    PASTE_DELAY = 0.3
    
    def __init__(self):
        self._is_windows = sys.platform == "win32"
        self._pyautogui = None
    
    def _get_pyautogui(self):
        """Lazy load pyautogui to avoid import overhead."""
        if self._pyautogui is None:
            try:
                import pyautogui
                # Fail-safe: move mouse to corner to abort
                pyautogui.FAILSAFE = True
                # Faster operations
                pyautogui.PAUSE = 0.05
                self._pyautogui = pyautogui
            except ImportError:
                raise RuntimeError(
                    "pyautogui is required for auto-injection. "
                    "Install with: pip install pyautogui"
                )
        return self._pyautogui
    
    def inject(
        self,
        prompt: str,
        target_ide: Optional[DetectedIDE] = None,
        auto_submit: bool = False
    ) -> InjectionReport:
        """
        Inject a prompt into the IDE's AI chat.
        
        Args:
            prompt: The prompt text to inject
            target_ide: Specific IDE to target (auto-detect if None)
            auto_submit: Whether to press Enter after pasting
        
        Returns:
            InjectionReport with the result
        """
        # Always copy to clipboard first (fallback)
        pyperclip.copy(prompt)
        
        # Detect IDE if not specified
        if target_ide is None:
            target_ide = detect_preferred_ide()
        
        if target_ide is None:
            return InjectionReport(
                result=InjectionResult.FALLBACK_CLIPBOARD,
                message="No supported IDE detected. Prompt copied to clipboard.",
                prompt_in_clipboard=True
            )
        
        # Try to inject
        try:
            success = self._inject_to_ide(target_ide, auto_submit)
            
            if success:
                return InjectionReport(
                    result=InjectionResult.SUCCESS,
                    ide=target_ide,
                    message=f"Prompt injected into {target_ide.display_name}",
                    prompt_in_clipboard=True
                )
            else:
                return InjectionReport(
                    result=InjectionResult.FALLBACK_CLIPBOARD,
                    ide=target_ide,
                    message=f"Could not inject into {target_ide.display_name}. Prompt copied to clipboard.",
                    prompt_in_clipboard=True
                )
        
        except Exception as e:
            return InjectionReport(
                result=InjectionResult.INJECTION_FAILED,
                ide=target_ide,
                message=f"Injection failed: {str(e)}. Prompt copied to clipboard.",
                prompt_in_clipboard=True
            )
    
    def _inject_to_ide(self, ide: DetectedIDE, auto_submit: bool) -> bool:
        """Perform the actual injection."""
        pyautogui = self._get_pyautogui()
        
        # Step 1: Focus the IDE window
        if not self._focus_window(ide):
            return False
        
        time.sleep(self.FOCUS_DELAY)
        
        # Step 2: Open AI chat with keyboard shortcut
        shortcut = ide.chat_shortcut
        if shortcut:
            self._send_shortcut(shortcut)
            time.sleep(self.SHORTCUT_DELAY)
        
        # Step 3: Paste the prompt
        # Use Ctrl+V (Windows/Linux) or Cmd+V (macOS)
        if sys.platform == "darwin":
            pyautogui.hotkey("command", "v")
        else:
            pyautogui.hotkey("ctrl", "v")
        
        time.sleep(self.PASTE_DELAY)
        
        # Step 4: Optionally submit
        if auto_submit:
            pyautogui.press("enter")
        
        return True
    
    def _focus_window(self, ide: DetectedIDE) -> bool:
        """Focus the IDE window."""
        if self._is_windows and ide.window_handle:
            return self._focus_window_windows(ide.window_handle)
        else:
            return self._focus_window_by_title(ide.window_title)
    
    def _focus_window_windows(self, handle: int) -> bool:
        """Focus window by handle on Windows."""
        try:
            import ctypes
            user32 = ctypes.windll.user32
            
            # Show window if minimized
            SW_RESTORE = 9
            user32.ShowWindow(handle, SW_RESTORE)
            
            # Bring to foreground
            user32.SetForegroundWindow(handle)
            
            return True
        except Exception:
            return False
    
    def _focus_window_by_title(self, title: str) -> bool:
        """Focus window by title (cross-platform fallback)."""
        pyautogui = self._get_pyautogui()
        
        try:
            # Try to find and activate window by title
            windows = pyautogui.getWindowsWithTitle(title)
            if windows:
                windows[0].activate()
                return True
        except Exception:
            pass
        
        return False
    
    def _send_shortcut(self, shortcut: str) -> None:
        """Send a keyboard shortcut."""
        pyautogui = self._get_pyautogui()
        
        # Parse shortcut string like "ctrl+shift+l"
        keys = shortcut.lower().split('+')
        pyautogui.hotkey(*keys)


def inject_prompt(
    prompt: str,
    target_ide: Optional[DetectedIDE] = None,
    auto_submit: bool = False
) -> InjectionReport:
    """
    Convenience function to inject a prompt.
    
    Args:
        prompt: The prompt text to inject
        target_ide: Specific IDE to target (auto-detect if None)
        auto_submit: Whether to press Enter after pasting
    
    Returns:
        InjectionReport with the result
    """
    return PromptInjector().inject(prompt, target_ide, auto_submit)


def copy_to_clipboard(prompt: str) -> None:
    """Simple clipboard fallback."""
    pyperclip.copy(prompt)
