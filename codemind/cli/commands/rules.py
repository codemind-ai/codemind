"""Rules command module."""

import sys
from pathlib import Path

import click

from ...ui import terminal


@click.group()
def rules():
    """Rule management commands."""
    pass


@rules.command("list")
@click.option("--preset", "-p", default=None, help="Show rules from a specific preset")
def rules_list(preset: str):
    """List available rules and presets.
    
    Shows all rule presets and their rules. Use --preset to filter.
    
    Examples:
      codemind rules list                  # Show all presets
      codemind rules list --preset security-strict  # Show security rules
    """
    terminal.print_header()
    
    from ...rules.presets import get_preset, list_presets
    
    if preset:
        try:
            rules_list = get_preset(preset)
            terminal.console.print(f"\n[bold]📋 {preset}[/bold] ({len(rules_list)} rules)\n")
            
            for rule in rules_list:
                icon = {"critical": "🚨", "warning": "⚠️", "info": "ℹ️"}.get(
                    rule.severity.value, "•"
                )
                terminal.console.print(f"  {icon} [cyan]{rule.name}[/cyan]")
                terminal.console.print(f"     {rule.description}")
                if rule.pattern:
                    terminal.console.print(f"     [dim]Pattern: {rule.pattern[:50]}...[/dim]")
                terminal.console.print()
        except ValueError as e:
            terminal.print_error(str(e))
            sys.exit(1)
    else:
        terminal.console.print("\n[bold]📋 Available Rule Presets[/bold]\n")
        
        presets_info = list_presets()
        for name, count in presets_info.items():
            terminal.console.print(f"  • [cyan]{name}[/cyan] ({count} rules)")
        
        terminal.console.print("\n[dim]Use --preset <name> to see rules in a preset.[/dim]")


@rules.command("check")
@click.option("--preset", "-p", default="minimal", help="Preset to use for checking")
@click.option("--file", "-f", default=None, help="Specific file to check")
def rules_check(preset: str, file: str):
    """Run rule checks on staged changes or a file.
    
    Examples:
      codemind rules check                 # Check staged changes
      codemind rules check -p security-strict  # Use security preset
      codemind rules check -f main.py      # Check specific file
    """
    terminal.print_header()
    
    from ...rules.engine import RuleEngine
    from ...rules.presets import get_preset
    
    try:
        rules_list = get_preset(preset)
    except ValueError as e:
        terminal.print_error(str(e))
        sys.exit(1)
    
    engine = RuleEngine(rules_list)
    terminal.console.print(f"\n[bold]🔍 Running {preset} ruleset ({len(rules_list)} rules)[/bold]\n")
    
    matches = []
    
    if file:
        # Check specific file
        file_path = Path.cwd() / file
        if not file_path.exists():
            terminal.print_error(f"File not found: {file}")
            sys.exit(1)
        
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        matches = engine.evaluate_file(file, content)
    else:
        # Check staged changes
        from ...commit.generator import get_staged_diff
        staged = get_staged_diff()
        
        if staged.is_empty:
            terminal.print_warning("No staged changes to check.")
            terminal.console.print("[dim]Stage files with: git add <files>[/dim]")
            return
        
        matches = engine.evaluate_diff(staged.diff)
    
    # Display results
    if not matches:
        terminal.print_success("No issues found!")
    else:
        summary = engine.get_summary(matches)
        
        if summary["critical"] > 0:
            terminal.console.print(f"[red]🚨 {summary['critical']} critical issues[/red]")
        if summary["warnings"] > 0:
            terminal.console.print(f"[yellow]⚠️ {summary['warnings']} warnings[/yellow]")
        if summary["info"] > 0:
            terminal.console.print(f"[blue]ℹ️ {summary['info']} suggestions[/blue]")
        
        terminal.console.print()
        
        for match in matches:
            icon = {"critical": "🚨", "warning": "⚠️", "info": "ℹ️"}.get(
                match.rule.severity.value, "•"
            )
            terminal.console.print(
                f"  {icon} [{match.rule.severity.value}] {match.message}"
            )
            terminal.console.print(f"     [dim]{match.file}[/dim]")
