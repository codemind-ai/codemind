"""IDE window detection module.

Detects running IDE windows with AI capabilities.
"""

import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class IDEType(Enum):
    """Supported IDE types."""
    CURSOR = "cursor"
    CLAUDE_CODE = "claude-code"
    WINDSURF = "windsurf"
    VSCODE = "vscode"
    UNKNOWN = "unknown"


# Map config names to IDEType
IDE_TYPE_MAP = {
    "cursor": IDEType.CURSOR,
    "claude-code": IDEType.CLAUDE_CODE,
    "windsurf": IDEType.WINDSURF,
    "vscode": IDEType.VSCODE,
}


@dataclass
class DetectedIDE:
    """A detected IDE window."""
    ide_type: IDEType
    window_title: str
    window_handle: Optional[int] = None
    process_name: Optional[str] = None
    
    @property
    def display_name(self) -> str:
        """Human-readable name for the IDE."""
        names = {
            IDEType.CURSOR: "Cursor",
            IDEType.CLAUDE_CODE: "Claude Code",
            IDEType.WINDSURF: "Windsurf",
            IDEType.VSCODE: "VS Code",
            IDEType.UNKNOWN: "Unknown IDE"
        }
        return names.get(self.ide_type, "Unknown")
    
    @property
    def chat_shortcut(self) -> Optional[str]:
        """Keyboard shortcut to open AI chat in this IDE."""
        shortcuts = {
            IDEType.CURSOR: "ctrl+l",  # Open Composer/Chat
            IDEType.CLAUDE_CODE: "ctrl+shift+p",  # Command palette (then type)
            IDEType.WINDSURF: "ctrl+l",  # Similar to Cursor
            IDEType.VSCODE: "ctrl+shift+i",  # Copilot Chat (if installed)
        }
        return shortcuts.get(self.ide_type)


# Window title patterns for detection
IDE_PATTERNS = {
    IDEType.CURSOR: ["Cursor", "cursor"],
    IDEType.CLAUDE_CODE: ["Claude", "claude"],
    IDEType.WINDSURF: ["Windsurf", "windsurf"],
    IDEType.VSCODE: ["Visual Studio Code", "VS Code", "Code - "],
}


class IDEDetector:
    """Detects running IDE windows."""
    
    def __init__(self):
        self._is_windows = sys.platform == "win32"
    
    def detect_all(self) -> list[DetectedIDE]:
        """Detect all running IDE windows."""
        if self._is_windows:
            return self._detect_windows()
        else:
            return self._detect_unix()
    
    def detect_preferred(self, preference: list[IDEType] = None) -> Optional[DetectedIDE]:
        """
        Detect the preferred IDE based on priority list.
        
        Args:
            preference: List of IDE types in priority order
                       (default: Cursor > Claude Code > Windsurf > VS Code)
        
        Returns:
            First matching IDE, or None if none found
        """
        if preference is None:
            preference = [
                IDEType.CURSOR,
                IDEType.CLAUDE_CODE,
                IDEType.WINDSURF,
                IDEType.VSCODE
            ]
        
        detected = self.detect_all()
        
        for ide_type in preference:
            for ide in detected:
                if ide.ide_type == ide_type:
                    return ide
        
        # Return first detected if no preference match
        return detected[0] if detected else None
    
    def _detect_windows(self) -> list[DetectedIDE]:
        """Detect IDEs on Windows using PowerShell."""
        detected = []
        
        try:
            # Get all visible windows with titles
            ps_script = '''
            Add-Type @"
                using System;
                using System.Runtime.InteropServices;
                using System.Text;
                public class Win32 {
                    [DllImport("user32.dll")]
                    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
                    
                    [DllImport("user32.dll")]
                    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
                    
                    [DllImport("user32.dll")]
                    public static extern bool IsWindowVisible(IntPtr hWnd);
                    
                    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
                }
"@
            
            $windows = @()
            $callback = {
                param($hwnd, $lparam)
                if ([Win32]::IsWindowVisible($hwnd)) {
                    $sb = New-Object System.Text.StringBuilder 256
                    [Win32]::GetWindowText($hwnd, $sb, 256) | Out-Null
                    $title = $sb.ToString()
                    if ($title) {
                        $script:windows += @{Handle=$hwnd.ToInt64(); Title=$title}
                    }
                }
                return $true
            }
            
            [Win32]::EnumWindows($callback, [IntPtr]::Zero) | Out-Null
            $windows | ForEach-Object { "$($_.Handle)|$($_.Title)" }
            '''
            
            result = subprocess.run(
                ["powershell", "-Command", ps_script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if '|' in line:
                        parts = line.split('|', 1)
                        if len(parts) == 2:
                            handle = int(parts[0])
                            title = parts[1]
                            ide = self._identify_ide(title, handle)
                            if ide:
                                detected.append(ide)
        
        except Exception:
            # Fallback: simple process-based detection
            detected = self._detect_windows_fallback()
        
        return detected
    
    def _detect_windows_fallback(self) -> list[DetectedIDE]:
        """Fallback detection using tasklist."""
        detected = []
        
        try:
            result = subprocess.run(
                ["tasklist", "/FO", "CSV", "/V"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    for ide_type, patterns in IDE_PATTERNS.items():
                        for pattern in patterns:
                            if pattern.lower() in line.lower():
                                # Extract window title from CSV
                                parts = line.split('","')
                                if len(parts) >= 9:
                                    title = parts[8].strip('"')
                                    detected.append(DetectedIDE(
                                        ide_type=ide_type,
                                        window_title=title,
                                        process_name=parts[0].strip('"')
                                    ))
                                break
        except Exception:
            pass
        
        return detected
    
    def _detect_unix(self) -> list[DetectedIDE]:
        """Detect IDEs on Unix-like systems (macOS, Linux)."""
        detected = []
        
        try:
            # Try wmctrl first (Linux)
            result = subprocess.run(
                ["wmctrl", "-l"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    parts = line.split(None, 3)
                    if len(parts) >= 4:
                        handle = int(parts[0], 16)
                        title = parts[3]
                        ide = self._identify_ide(title, handle)
                        if ide:
                            detected.append(ide)
                return detected
        except FileNotFoundError:
            pass
        except Exception:
            pass
        
        try:
            # Fallback: ps with grep
            for ide_type, patterns in IDE_PATTERNS.items():
                for pattern in patterns:
                    result = subprocess.run(
                        ["pgrep", "-f", pattern.lower()],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        detected.append(DetectedIDE(
                            ide_type=ide_type,
                            window_title=f"{pattern} (detected by process)",
                            process_name=pattern.lower()
                        ))
        except Exception:
            pass
        
        return detected
    
    def _identify_ide(self, title: str, handle: int = None) -> Optional[DetectedIDE]:
        """Identify IDE type from window title."""
        title_lower = title.lower()
        
        for ide_type, patterns in IDE_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in title_lower:
                    return DetectedIDE(
                        ide_type=ide_type,
                        window_title=title,
                        window_handle=handle
                    )
        
        return None


def detect_ides() -> list[DetectedIDE]:
    """Convenience function to detect all IDEs."""
    return IDEDetector().detect_all()


def detect_preferred_ide(preference: list[IDEType] = None) -> Optional[DetectedIDE]:
    """Convenience function to detect preferred IDE."""
    return IDEDetector().detect_preferred(preference)
