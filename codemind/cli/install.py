"""Git hook installer module.

Installs and manages the pre-push git hook.
"""

import stat
from pathlib import Path
from typing import Optional


# Hook script template
HOOK_TEMPLATE = '''#!/bin/sh
# codemind AI - Pre-push hook
# Automatically installed by: codemind install
# To uninstall, run: codemind uninstall

# Redirect stdin from terminal for interactive prompts
exec < /dev/tty

# Check if codemind is available
if ! command -v codemind &> /dev/null; then
    # Try Python module
    if python -m codemind.cli.main --version &> /dev/null; then
        python -m codemind.cli.main run --hook
        exit $?
    fi
    echo "⚠️  codemind AI not found. Skipping review."
    exit 0
fi

# Run the review
codemind run --hook
exit $?
'''

# Windows batch script template  
HOOK_TEMPLATE_WINDOWS = '''@echo off
:: codemind AI - Pre-push hook (Windows)
:: Automatically installed by: codemind install
:: To uninstall, run: codemind uninstall

where codemind >nul 2>nul
if %errorlevel%==0 (
    codemind run --hook < CON
    exit /b %errorlevel%
)

python -m codemind.cli.main run --hook < CON
exit /b %errorlevel%
'''


class HookInstaller:
    """Installs git hooks for codemind AI."""
    
    HOOK_NAME = "pre-push"
    HOOK_MARKER = "# codemind AI"
    
    def __init__(self, repo_path: Optional[Path] = None):
        self.repo_path = repo_path or Path.cwd()
    
    def get_hooks_dir(self) -> Path:
        """Get the .git/hooks directory."""
        git_dir = self.repo_path / ".git"
        
        if not git_dir.exists():
            raise RuntimeError(f"Not a git repository: {self.repo_path}")
        
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(exist_ok=True)
        
        return hooks_dir
    
    def get_hook_path(self) -> Path:
        """Get the path to the pre-push hook."""
        return self.get_hooks_dir() / self.HOOK_NAME
    
    def is_installed(self) -> bool:
        """Check if codemind hook is installed."""
        hook_path = self.get_hook_path()
        
        if not hook_path.exists():
            return False
        
        content = hook_path.read_text(encoding="utf-8", errors="replace")
        return self.HOOK_MARKER in content
    
    def has_existing_hook(self) -> bool:
        """Check if there's an existing (non-codemind) hook."""
        hook_path = self.get_hook_path()
        
        if not hook_path.exists():
            return False
        
        content = hook_path.read_text(encoding="utf-8", errors="replace")
        return self.HOOK_MARKER not in content
    
    def install(self, force: bool = False) -> tuple[bool, str]:
        """
        Install the pre-push hook.
        
        Args:
            force: Overwrite existing hook if present
        
        Returns:
            (success, message) tuple
        """
        hook_path = self.get_hook_path()
        
        # Check for existing hook
        if hook_path.exists():
            if self.is_installed() and not force:
                return True, "codemind hook is already installed. Use --force to update."
            
            if self.has_existing_hook() and not force:
                return False, (
                    f"Existing pre-push hook found at {hook_path}. "
                    "Use --force to overwrite."
                )
        
        # Write the hook
        import sys
        if sys.platform == "win32":
            # On Windows, create both .sh and .bat versions
            hook_path.write_text(HOOK_TEMPLATE, encoding="utf-8")
            # Also create Windows batch version
            bat_path = hook_path.with_suffix(".bat")
            bat_path.write_text(HOOK_TEMPLATE_WINDOWS, encoding="utf-8")
        else:
            hook_path.write_text(HOOK_TEMPLATE, encoding="utf-8")
        
        # Make executable (Unix)
        hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        
        return True, f"✅ codemind hook installed at {hook_path}"
    
    def uninstall(self) -> tuple[bool, str]:
        """
        Uninstall the pre-push hook.
        
        Returns:
            (success, message) tuple
        """
        hook_path = self.get_hook_path()
        
        if not hook_path.exists():
            return True, "No pre-push hook found."
        
        if not self.is_installed():
            return False, (
                "Existing hook is not a codemind hook. "
                "Manual removal required."
            )
        
        # Remove the hook
        hook_path.unlink()
        
        # Remove Windows batch version if exists
        bat_path = hook_path.with_suffix(".bat")
        if bat_path.exists():
            bat_path.unlink()
        
        return True, "✅ codemind hook uninstalled."


def install_hook(repo_path: Optional[Path] = None, force: bool = False) -> tuple[bool, str]:
    """Convenience function to install hook."""
    return HookInstaller(repo_path).install(force)


def uninstall_hook(repo_path: Optional[Path] = None) -> tuple[bool, str]:
    """Convenience function to uninstall hook."""
    return HookInstaller(repo_path).uninstall()


def is_hook_installed(repo_path: Optional[Path] = None) -> bool:
    """Convenience function to check if hook is installed."""
    return HookInstaller(repo_path).is_installed()
