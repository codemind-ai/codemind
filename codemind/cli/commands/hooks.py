"""Hooks command module."""

import click
from ...cli.install import install_hook, uninstall_hook
from ...ui import terminal


@click.command()
@click.option("--force", "-f", is_flag=True, help="Force installation (overwrite existing hook)")
def install(force: bool):
    """Install the git pre-push hook."""
    terminal.print_header()
    try:
        if install_hook(force=force):
            terminal.print_success("Git pre-push hook installed successfully!")
        else:
            terminal.print_warning("Hook installation cancelled (already exists).")
            terminal.console.print("[dim]Use --force to overwrite.[/dim]")
    except Exception as e:
        terminal.print_error(f"Failed to install hook: {e}")


@click.command()
def uninstall():
    """Remove the git pre-push hook."""
    terminal.print_header()
    try:
        if uninstall_hook():
            terminal.print_success("Git pre-push hook removed.")
        else:
            terminal.print_info("No hook found to remove.")
    except Exception as e:
        terminal.print_error(f"Failed to remove hook: {e}")
