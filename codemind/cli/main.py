"""codemind AI - Main CLI entrypoint.

Usage:
    codemind install      Install git pre-push hook
    codemind uninstall    Remove git pre-push hook
    codemind run          Manually run review on current changes
    codemind config       Show or edit configuration
"""

import sys
from pathlib import Path
from typing import Optional

import click

from .. import __version__
from ..git.diff import get_diff, DiffResult, DiffExtractor
from ..git.context import get_context, GitContext
from ..prompt.builder import build_prompt, PromptConfig
from ..ide.detect import detect_preferred_ide, IDEType
from ..ide.inject import inject_prompt, InjectionResult
from ..cli.config import load_config, get_default_config_content, get_default_template_content
from ..cli.install import install_hook, uninstall_hook, is_hook_installed
from ..history import save_review, get_recent_reviews, get_review_stats, clear_history
from ..ui import terminal


# Map config IDE names to IDEType
IDE_TYPE_MAP = {
    "cursor": IDEType.CURSOR,
    "claude-code": IDEType.CLAUDE_CODE,
    "windsurf": IDEType.WINDSURF,
    "vscode": IDEType.VSCODE,
}


@click.group()
@click.version_option(version=__version__, prog_name="codemind AI")
def cli():
    """🚀 codemind AI - Pre-push AI code review orchestrator."""
    pass


@cli.command()
@click.option("--force", "-f", is_flag=True, help="Overwrite existing hook")
def install(force: bool):
    """Install the git pre-push hook."""
    terminal.print_header()
    
    try:
        success, message = install_hook(force=force)
        if success:
            terminal.print_success(message)
        else:
            terminal.print_error(message)
            sys.exit(1)
    except RuntimeError as e:
        terminal.print_error(str(e))
        sys.exit(1)


@cli.command()
def uninstall():
    """Remove the git pre-push hook."""
    terminal.print_header()
    
    try:
        success, message = uninstall_hook()
        if success:
            terminal.print_success(message)
        else:
            terminal.print_error(message)
            sys.exit(1)
    except RuntimeError as e:
        terminal.print_error(str(e))
        sys.exit(1)


@cli.command()
@click.option("--hook", is_flag=True, hidden=True, help="Called from git hook")
@click.option("--base", "-b", default=None, help="Base ref for diff (default: auto-detect)")
@click.option("--no-inject", is_flag=True, help="Don't auto-inject, just copy to clipboard")
@click.option("--dry-run", is_flag=True, help="Show what would happen without injecting")
@click.option("--preview", is_flag=True, help="Show the prompt before injecting")
def run(hook: bool, base: Optional[str], no_inject: bool, dry_run: bool, preview: bool):
    """Run AI code review on current changes."""
    terminal.print_header()
    
    try:
        # Load config
        config = load_config()
        
        # Get git context
        context = get_context()
        
        # Get diff
        diff = get_diff(base=base)
        
        if diff.is_empty:
            terminal.print_info("No changes to review.")
            sys.exit(0)
        
        # Show diff summary
        terminal.print_diff_summary(diff)
        
        # Check if review should run
        if config.enabled == "never":
            terminal.print_info("Review disabled in config. Continuing...")
            sys.exit(0)
        
        if config.enabled == "ask" and not hook:
            choice = terminal.ask_review()
            if choice == 'n':
                terminal.print_push_continuing()
                sys.exit(0)
            elif choice == 's':
                terminal.print_info("Skipping review this time.")
                sys.exit(0)
        
        # Check diff size warning
        extractor = DiffExtractor()
        warning = extractor.check_size_warning(diff)
        if warning:
            terminal.print_warning(warning)
        
        # Build prompt with custom template if configured
        template_path = None
        if config.prompt.template_path:
            template_path = Path(config.prompt.template_path)
            if not template_path.is_absolute():
                # Resolve relative to config file directory
                if config.config_path:
                    template_path = config.config_path.parent / template_path
                else:
                    template_path = Path.cwd() / template_path
        
        prompt_config = PromptConfig(
            max_comments=config.review.max_comments,
            strict_format=config.review.strict_format,
            template_path=template_path,
            extra_rules=config.prompt.extra_rules,
        )
        built_prompt = build_prompt(diff, context, prompt_config)
        
        if built_prompt.warning:
            terminal.print_warning(built_prompt.warning)
        
        # Preview mode: show the prompt
        if preview or dry_run:
            terminal.console.print("\n[bold cyan]━━━ Prompt Preview ━━━[/bold cyan]\n")
            terminal.console.print(built_prompt.content[:2000])
            if len(built_prompt.content) > 2000:
                terminal.console.print(f"\n[dim]... ({len(built_prompt.content) - 2000} more chars)[/dim]")
            terminal.console.print("\n[bold cyan]━━━━━━━━━━━━━━━━━━━━━[/bold cyan]\n")
            terminal.console.print(f"[dim]Token estimate: ~{built_prompt.token_estimate}[/dim]")
        
        # Dry-run mode: exit before injection
        if dry_run:
            terminal.print_info("Dry run complete. No prompt was injected.")
            sys.exit(0)
        
        # Inject or copy prompt
        if no_inject or not config.ide.auto_inject:
            # Just copy to clipboard
            from ..ide.inject import copy_to_clipboard
            copy_to_clipboard(built_prompt.content)
            terminal.print_prompt_ready()
        else:
            # Auto-inject
            preference = [
                IDE_TYPE_MAP.get(name, IDEType.UNKNOWN)
                for name in config.ide.preferred
            ]
            
            report = inject_prompt(
                built_prompt.content,
                auto_submit=config.ide.auto_submit
            )
            
            if report.result == InjectionResult.SUCCESS:
                terminal.print_prompt_ready(report.ide.display_name)
            else:
                terminal.print_prompt_ready()  # Fallback message
        
        # Save to history
        save_review(
            branch=context.current_branch if context else "unknown",
            files_changed=diff.total_files,
            lines_added=diff.total_additions,
            lines_deleted=diff.total_deletions,
            token_estimate=built_prompt.token_estimate,
            prompt_content=built_prompt.content,
            files=[f.path for f in diff.files[:10]]  # Store first 10 files
        )
        
        # Wait for user to complete review
        terminal.wait_for_review()
        
        # Ask to proceed
        if terminal.confirm_push():
            terminal.print_push_continuing()
            sys.exit(0)
        else:
            terminal.print_push_aborted()
            sys.exit(1)
    
    except RuntimeError as e:
        terminal.print_error(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        terminal.print_info("\nInterrupted.")
        sys.exit(1)


@cli.command()
@click.option("--init", is_flag=True, help="Create default config file")
@click.option("--show", is_flag=True, help="Show current config")
def config(init: bool, show: bool):
    """Show or create configuration."""
    terminal.print_header()
    
    if init:
        config_path = Path.cwd() / ".codemind.yml"
        if config_path.exists():
            terminal.print_warning(f"Config already exists: {config_path}")
            sys.exit(1)
        
        config_path.write_text(get_default_config_content(), encoding="utf-8")
        terminal.print_success(f"Created config: {config_path}")
    
    elif show:
        cfg = load_config()
        if cfg.config_path:
            terminal.print_info(f"Config loaded from: {cfg.config_path}")
            click.echo()
            click.echo(cfg.config_path.read_text(encoding="utf-8"))
        else:
            terminal.print_info("No config file found. Using defaults.")
            click.echo()
            click.echo(get_default_config_content())
    
    else:
        # Show status
        cfg = load_config()
        if cfg.config_path:
            terminal.print_success(f"Config: {cfg.config_path}")
        else:
            terminal.print_info("No config file. Use --init to create one.")
        
        if is_hook_installed():
            terminal.print_success("Hook: installed")
        else:
            terminal.print_warning("Hook: not installed (run 'codemind install')")


@cli.command()
@click.option("--export", "-e", is_flag=True, help="Export default template to file")
@click.option("--output", "-o", default="codemind-template.txt", help="Output file name")
@click.option("--show", is_flag=True, help="Show default template")
def template(export: bool, output: str, show: bool):
    """Manage prompt templates."""
    terminal.print_header()
    
    if export:
        output_path = Path.cwd() / output
        if output_path.exists():
            terminal.print_warning(f"File already exists: {output_path}")
            if not click.confirm("Overwrite?"):
                sys.exit(0)
        
        output_path.write_text(get_default_template_content(), encoding="utf-8")
        terminal.print_success(f"Template exported to: {output_path}")
        terminal.console.print(f"\n[dim]To use this template, add to .codemind.yml:[/dim]")
        terminal.console.print(f"[cyan]prompt:\n  template_path: {output}[/cyan]")
    
    elif show:
        terminal.console.print("\n[bold cyan]━━━ Default Template ━━━[/bold cyan]\n")
        content = get_default_template_content()
        terminal.console.print(content)
        terminal.console.print(f"\n[dim]({len(content)} chars)[/dim]")
    
    else:
        terminal.print_info("Use --export to create a custom template or --show to view default.")
        terminal.console.print("\n[dim]Available placeholders in templates:[/dim]")
        terminal.console.print("  • {max_comments} - Max number of comments")
        terminal.console.print("  • {branch_name} - Current branch name")
        terminal.console.print("  • {file_count} - Number of files changed")
        terminal.console.print("  • {additions} - Lines added")
        terminal.console.print("  • {deletions} - Lines deleted")
        terminal.console.print("  • {diff_content} - The actual diff")


@cli.command()
def status():
    """Show codemind AI status."""
    terminal.print_header()
    
    # Config status
    cfg = load_config()
    if cfg.config_path:
        terminal.print_success(f"Config: {cfg.config_path}")
    else:
        terminal.print_info("Config: using defaults")
    
    # Hook status
    try:
        if is_hook_installed():
            terminal.print_success("Hook: installed")
        else:
            terminal.print_warning("Hook: not installed")
    except RuntimeError:
        terminal.print_warning("Hook: not in a git repository")
    
    # IDE detection
    ide = detect_preferred_ide()
    if ide:
        terminal.print_success(f"IDE detected: {ide.display_name}")
    else:
        terminal.print_warning("No supported IDE detected")


@cli.command()
def detect():
    """Detect running IDEs and show details."""
    terminal.print_header()
    
    from ..ide.detect import detect_ides
    
    ides = detect_ides()
    
    if not ides:
        terminal.print_warning("No supported IDEs detected.")
        terminal.console.print("\n[dim]Supported IDEs: Cursor, Claude Code, Windsurf, VS Code[/dim]")
        sys.exit(0)
    
    terminal.print_success(f"Found {len(ides)} IDE(s):\n")
    
    for ide in ides:
        terminal.console.print(f"  [bold]{ide.display_name}[/bold]")
        terminal.console.print(f"    Window: [dim]{ide.window_title[:60]}...[/dim]" if len(ide.window_title) > 60 else f"    Window: [dim]{ide.window_title}[/dim]")
        if ide.chat_shortcut:
            terminal.console.print(f"    Chat shortcut: [cyan]{ide.chat_shortcut}[/cyan]")
        terminal.console.print()


@cli.command()
@click.option("--list", "-l", "show_list", is_flag=True, help="Show recent reviews")
@click.option("--stats", "-s", is_flag=True, help="Show review statistics")
@click.option("--clear", is_flag=True, help="Clear all history")
@click.option("--count", "-n", default=10, help="Number of entries to show")
def history(show_list: bool, stats: bool, clear: bool, count: int):
    """View review history and statistics."""
    terminal.print_header()
    
    if clear:
        if click.confirm("Clear all review history?"):
            cleared = clear_history()
            terminal.print_success(f"Cleared {cleared} history entries.")
        sys.exit(0)
    
    if stats:
        review_stats = get_review_stats()
        if review_stats["total_reviews"] == 0:
            terminal.print_info("No reviews in history yet.")
            sys.exit(0)
        
        terminal.console.print("\n[bold]📊 Review Statistics[/bold]\n")
        terminal.console.print(f"  Total reviews: [cyan]{review_stats['total_reviews']}[/cyan]")
        terminal.console.print(f"  Files reviewed: [cyan]{review_stats['total_files_reviewed']}[/cyan]")
        terminal.console.print(f"  Lines changed: [cyan]{review_stats['total_lines_changed']}[/cyan]")
        terminal.console.print(f"  Avg files/review: [cyan]{review_stats['avg_files_per_review']:.1f}[/cyan]")
        terminal.console.print(f"\n  First review: [dim]{review_stats['first_review'][:10]}[/dim]")
        terminal.console.print(f"  Last review: [dim]{review_stats['last_review'][:10]}[/dim]")
        sys.exit(0)
    
    # Default: show recent reviews
    reviews = get_recent_reviews(count)
    if not reviews:
        terminal.print_info("No reviews in history yet.")
        terminal.console.print("[dim]Run 'codemind run' to create your first review.[/dim]")
        sys.exit(0)
    
    terminal.console.print(f"\n[bold]📋 Recent Reviews ({len(reviews)})[/bold]\n")
    
    for entry in reversed(reviews):  # Most recent first
        date_str = entry.timestamp[:10]
        time_str = entry.timestamp[11:16]
        terminal.console.print(
            f"  [dim]{date_str} {time_str}[/dim]  "
            f"[cyan]{entry.branch}[/cyan]  "
            f"[green]+{entry.lines_added}[/green]/[red]-{entry.lines_deleted}[/red]  "
            f"[dim]{entry.files_changed} files[/dim]"
        )


@cli.command()
@click.option("--transport", "-t", default="stdio", type=click.Choice(["stdio", "streamable-http"]), help="Transport type")
@click.option("--host", default="localhost", help="Host for HTTP transport")
@click.option("--port", default=8000, help="Port for HTTP transport")
def serve(transport: str, host: str, port: int):
    """Run CodeMind as an MCP server.
    
    This exposes CodeMind functionality via the Model Context Protocol (MCP),
    allowing AI clients to use CodeMind tools for code review.
    
    Tools available:
      - review_diff: Generate review prompt for git changes
      - validate_ai_response: Validate AI review output
      - get_review_history: Get recent reviews
      - get_git_context: Get git repository info
    """
    terminal.print_header()
    terminal.console.print("[bold cyan]Starting MCP Server...[/bold cyan]\n")
    terminal.console.print(f"  Transport: [green]{transport}[/green]")
    if transport == "streamable-http":
        terminal.console.print(f"  Endpoint: [green]http://{host}:{port}/mcp[/green]")
    terminal.console.print("\n[dim]Press Ctrl+C to stop.[/dim]\n")
    
    try:
        from ..mcp.server import run_server
        run_server(transport=transport)
    except ImportError as e:
        terminal.print_error(f"MCP dependencies not installed: {e}")
        terminal.console.print("[dim]Install with: pip install codemind[mcp][/dim]")
        sys.exit(1)
    except KeyboardInterrupt:
        terminal.print_info("\nServer stopped.")


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
