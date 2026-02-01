"""Template command module."""

import click
from pathlib import Path
from ..config import get_default_template_content
from ...ui import terminal


@click.command()
@click.option("--export", "-e", is_flag=True, help="Export default template to file")
@click.option("--output", "-o", default="codemind-template.txt", help="Output file name")
@click.option("--show", "-s", is_flag=True, help="Show current template")
def template(export: bool, output: str, show: bool):
    """Manage prompt templates."""
    terminal.print_header()
    
    if export:
        out_path = Path.cwd() / output
        if out_path.exists():
            terminal.print_warning(f"File already exists: {out_path}")
            return
            
        out_path.write_text(get_default_template_content(), encoding="utf-8")
        terminal.print_success(f"Default template exported to: {out_path}")
        terminal.console.print("[dim]Use 'prompt.template_path' in .codemind.yml to use this template.[/dim]")
        
    elif show:
        terminal.console.print("\n[bold cyan]━━━ Default Template ━━━[/bold cyan]\n")
        terminal.console.print(get_default_template_content())
        terminal.console.print("\n[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]\n")
    else:
        terminal.print_info("Use --export to save the default template or --show to view it.")
