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
@click.option("--wizard", "-w", is_flag=True, help="Run interactive setup wizard")
def init(wizard: bool):
    """Create a default configuration file."""
    terminal.print_header()
    
    if wizard:
        run_wizard()
        return
        
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


def run_wizard():
    """Interactive onboarding wizard."""
    terminal.console.print("\n[bold cyan]✨ Welcome to the CodeMind Onboarding Wizard! ✨[/bold cyan]")
    terminal.console.print("[dim]We'll help you set up CodeMind for your project in 3 simple steps.[/dim]\n")
    
    # Step 1: IDE Detection
    terminal.console.print("[bold]Step 1: AI Provider[/bold]")
    use_standalone = click.confirm("Do you want to use a standalone LLM (OpenAI/Ollama) instead of an IDE's AI?")
    
    llm_node = ""
    if use_standalone:
        provider = click.prompt("Choose provider", type=click.Choice(["openai", "ollama"]), default="openai")
        if provider == "openai":
            model = click.prompt("Model (e.g. gpt-4o)", default="gpt-4o")
            api_key = click.prompt("OpenAI API Key (optional, will use env if empty)", default="", show_default=False)
            llm_node = f"\nllm:\n  provider: openai\n  model: {model}\n"
            if api_key:
                llm_node += f"  api_key: {api_key}\n"
        else:
            model = click.prompt("Ollama model (e.g. codellama)", default="codellama")
            llm_node = f"\nllm:\n  provider: ollama\n  model: {model}\n"
    
    # Step 2: Hook Installation
    terminal.console.print("\n[bold]Step 2: Workflow Integration[/bold]")
    install_hook = click.confirm("Do you want to install the Git pre-push hook now?")
    
    # Step 3: Rules
    terminal.console.print("\n[bold]Step 3: Review Rules[/bold]")
    preset = click.prompt("Choose a starting rule preset", type=click.Choice(["minimal", "security-strict", "python", "javascript"]), default="minimal")
    
    # Finalize
    config_path = Path.cwd() / ".codemind.yml"
    if config_path.exists():
        if not click.confirm(f"\n.codemind.yml already exists. Overwrite?"):
            terminal.print_info("Setup cancelled.")
            return

    base_config = get_default_config_content()
    # Inject wizard choices
    if llm_node:
        base_config += llm_node
    
    config_path.write_text(base_config, encoding="utf-8")
    terminal.print_success(f"Config created: {config_path}")
    
    if install_hook:
        from ..install import install_hook
        try:
            install_hook(force=True)
            terminal.print_success("Git pre-push hook installed!")
        except Exception as e:
            terminal.print_error(f"Failed to install hook: {e}")

    terminal.console.print("\n[bold green]🚀 You're all set! Try running 'codemind status' or 'codemind run'.[/bold green]")
