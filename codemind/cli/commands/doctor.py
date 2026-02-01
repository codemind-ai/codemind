"""Doctor command module."""

import sys
import platform
import subprocess
from pathlib import Path

import click
from ...ui import terminal


@click.command()
def doctor():
    """Check system health and diagnostic information."""
    terminal.print_header()
    terminal.console.print("\n[bold]🩺 CodeMind Doctor - Health Check[/bold]\n")
    
    # 1. System Info
    terminal.console.print(f"  [bold]System:[/bold] {platform.system()} {platform.release()}")
    terminal.console.print(f"  [bold]Python:[/bold] {sys.version.split()[0]}")
    
    # 2. Git Status
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        terminal.console.print("  [green]✓ git is available[/green]")
        
        # Check if in repo
        res = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], capture_output=True, text=True)
        if res.returncode == 0:
            terminal.console.print("  [green]✓ Current directory is a git repository[/green]")
        else:
            terminal.console.print("  [red]✗ Not a git repository[/red]")
    except Exception:
        terminal.console.print("  [red]✗ git is not installed or not in PATH[/red]")

    # 3. Hook Status
    from ..install import is_hook_installed
    if is_hook_installed():
        terminal.console.print("  [green]✓ Git pre-push hook is installed[/green]")
    else:
        terminal.console.print("  [yellow]⚠️  Git pre-push hook not installed (run 'codemind install')[/yellow]")

    # 4. Config Status
    from ..config import load_config
    try:
        config = load_config()
        if config.config_path:
            terminal.console.print(f"  [green]✓ Config loaded from {config.config_path}[/green]")
        else:
            terminal.console.print("  [blue]ℹ️  Config: using defaults (no .codemind.yml)[/blue]")
    except Exception as e:
        terminal.console.print(f"  [red]✗ Invalid configuration: {e}[/red]")

    # 5. IDE Status
    from ...ide.detect import detect_preferred_ide
    ide = detect_preferred_ide()
    if ide:
        terminal.console.print(f"  [green]✓ Detected running IDE: {ide.display_name}[/green]")
    else:
        terminal.console.print("  [yellow]⚠️  No supported AI IDE detected[/yellow]")

    # 6. LLM Connectivity (Standalone)
    if config.llm.provider != "ide":
        terminal.console.print(f"\n[bold]Checking Standalone LLM ({config.llm.provider})...[/bold]")
        from ...llm import get_llm_provider
        try:
            llm = get_llm_provider(
                provider_type=config.llm.provider,
                model=config.llm.model,
                api_key=config.llm.api_key,
                base_url=config.llm.base_url
            )
            # Test with a simple prompt
            with terminal.ui.spinner("Testing LLM connectivity..."):
                llm.generate("say 'ok'")
            terminal.console.print(f"  [green]✓ Connectivity to {config.llm.provider} successful[/green]")
        except Exception as e:
            terminal.console.print(f"  [red]✗ LLM connectivity failed: {e}[/red]")

    terminal.console.print("\n[bold green]Doctor's report complete![/bold green]")
    terminal.console.print("[dim]Use 'codemind status' for a quick summary or 'codemind help' for usage.[/dim]")
