"""Info command module."""

import click
from ...ide.detect import detect_preferred_ide
from ...cli.config import load_config
from ...cli.install import is_hook_installed
from ...ui import terminal


@click.command()
def detect():
    """Detect running IDEs and show details."""
    terminal.print_header()
    terminal.print_info("Detecting running AI-capable IDEs...")
    
    ide = detect_preferred_ide()
    if ide:
        terminal.console.print(f"\n[bold]Detected IDE:[/bold] {ide.display_name}")
        terminal.console.print(f"[bold]Window Title:[/bold] {ide.window_title or 'Unknown'}")
        
        if ide.process_name:
            terminal.console.print(f"[bold]Process:[/bold] {ide.process_name}")
    else:
        terminal.print_warning("No supported AI IDE detected.")
        terminal.console.print("[dim]Make sure your IDE (Cursor, Claude Code, Windsurf, or VS Code) is open and active.[/dim]")


@click.command()
def status():
    """Show codemind AI status."""
    terminal.print_header()
    
    # Check config
    cfg = load_config()
    if cfg.config_path:
        terminal.print_success(f"Config: {cfg.config_path}")
    else:
        terminal.print_info("Config: using defaults (no .codemind.yml found)")
    
    # Check hook
    if is_hook_installed():
        terminal.print_success("Hook: installed and active")
    else:
        terminal.print_warning("Hook: not installed (run 'codemind install')")
        
    # Check IDE
    ide = detect_preferred_ide()
    if ide:
        terminal.print_success(f"IDE: {ide.display_name} detected")
    else:
        terminal.print_warning("IDE: none detected (make sure your IDE is running)")
