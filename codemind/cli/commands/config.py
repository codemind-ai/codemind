"""Config command module."""

import sys
from pathlib import Path

import click

from ..config import load_config, get_default_config_content
from ..install import is_hook_installed
from ...ui import terminal


@click.group(invoke_without_command=True)
@click.pass_context
def config(ctx):
    """Configuration management commands."""
    if ctx.invoked_subcommand is None:
        # Default behavior: show status
        terminal.print_header()
        cfg = load_config()
        if cfg.config_path:
            terminal.print_success(f"Config: {cfg.config_path}")
        else:
            terminal.print_info("No config file. Use 'codemind config init' to create one.")
        
        if is_hook_installed():
            terminal.print_success("Hook: installed")
        else:
            terminal.print_warning("Hook: not installed (run 'codemind install')")


@config.command()
def init():
    """Create a default configuration file."""
    terminal.print_header()
    config_path = Path.cwd() / ".codemind.yml"
    if config_path.exists():
        terminal.print_warning(f"Config already exists: {config_path}")
        sys.exit(1)
    
    config_path.write_text(get_default_config_content(), encoding="utf-8")
    terminal.print_success(f"Created config: {config_path}")


@config.command()
def show():
    """Show current configuration content."""
    terminal.print_header()
    cfg = load_config()
    if cfg.config_path:
        terminal.print_info(f"Config loaded from: {cfg.config_path}")
        click.echo()
        click.echo(cfg.config_path.read_text(encoding="utf-8"))
    else:
        terminal.print_info("No config file found. Using defaults.")
        click.echo()
        click.echo(get_default_config_content())


@config.command()
@click.option("--output", "-o", default="codemind-shared.yml", help="Output file path")
def export(output: str):
    """Export current configuration for team sharing.
    
    Creates a portable configuration file that can be shared with team members.
    
    Examples:
      codemind config export
      codemind config export -o team-config.yml
    """
    terminal.print_header()
    from ...sharing.export import export_config
    
    output_path = Path.cwd() / output
    try:
        export_config(output_path)
        terminal.print_success(f"Configuration exported to: {output_path}")
    except Exception as e:
        terminal.print_error(f"Export failed: {e}")
        sys.exit(1)


@config.command("import")
@click.argument("source")
def config_import(source: str):
    """Import configuration from a file or URL.
    
    Args:
        source: File path or URL (https://...) to import from.
        
    Examples:
      codemind config import team-config.yml
      codemind config import https://example.com/codemind.yml
    """
    terminal.print_header()
    from ...sharing.import_config import import_config
    
    target_path = Path.cwd() / ".codemind.yml"
    
    if target_path.exists():
        if not click.confirm(f"Config file {target_path} already exists. Overwrite?"):
            terminal.print_info("Import cancelled.")
            return

    try:
        import_config(source, target_path)
        terminal.print_success(f"Configuration imported to: {target_path}")
    except Exception as e:
        terminal.print_error(f"Import failed: {e}")
        sys.exit(1)
