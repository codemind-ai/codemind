"""Commit command module."""

import sys
import click

from ...ui import terminal
from ...ide.inject import inject_prompt, InjectionResult
from ..config import load_config
from ...commit.generator import CommitStyle, get_staged_diff, generate_commit_prompt
from ...ide.detect import IDEType, IDE_TYPE_MAP


@click.command()
@click.option("--style", "-s", type=click.Choice(["conventional", "simple", "descriptive"]), default="conventional", help="Commit message style")
@click.option("--apply", "-a", is_flag=True, help="Apply the commit directly after generating")
@click.option("--no-inject", is_flag=True, help="Don't auto-inject to IDE, just copy to clipboard")
def commit(style: str, apply: bool, no_inject: bool):
    """Generate AI commit message from staged changes.
    
    Analyzes your staged changes (git add) and generates a commit message
    using your IDE's AI. The message follows your chosen style.
    
    Styles:
      conventional: type(scope): subject (feat: added x, fix: fixed y)
      simple: One-line concise summary
      descriptive: Multi-line detailed explanation
      
    Examples:
      codemind commit                    # Generate conventional commit
      codemind commit -s simple          # Generate simple commit
      codemind commit --apply            # Generate and commit directly
    """
    terminal.print_header()
    
    # Load config
    config = load_config()
    
    # Get staged changes
    staged = get_staged_diff()
    
    if staged.is_empty:
        terminal.print_warning("No staged changes found.")
        terminal.console.print("[dim]Use 'git add <files>' to stage changes before running this command.[/dim]")
        sys.exit(0)
    
    # Generate prompt
    mapping = {
        "conventional": CommitStyle.CONVENTIONAL,
        "simple": CommitStyle.SIMPLE,
        "descriptive": CommitStyle.DESCRIPTIVE,
    }
    commit_style = mapping.get(style, CommitStyle.CONVENTIONAL)
    
    prompt = generate_commit_prompt(staged, commit_style)
    
    # Inject or copy
    if no_inject or not config.ide.auto_inject:
        from ...ide.inject import copy_to_clipboard
        copy_to_clipboard(prompt.content)
        terminal.print_success("Commit message prompt copied to clipboard!")
    else:
        report = inject_prompt(
            prompt.content,
            auto_submit=config.ide.auto_submit
        )
        
        if report.result == InjectionResult.SUCCESS:
            terminal.print_prompt_ready(report.ide.display_name)
        else:
            terminal.print_prompt_ready()
            
    terminal.console.print(f"\n[bold]Style:[/bold] {style}")
    terminal.console.print(f"[bold]Files:[/bold] {staged.summary}")
    
    if apply:
        terminal.console.print("\n[yellow]Wait for AI to generate the message and paste it into git commit...[/yellow]")
        terminal.console.print("[dim]Note: --apply currently works by setting up the prompt, manual commit still needed if injection fails.[/dim]")
