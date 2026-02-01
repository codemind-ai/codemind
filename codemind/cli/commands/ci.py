"""CI command module."""

import sys
from pathlib import Path

import click

from ...ui import terminal


@click.group()
def ci():
    """CI/CD integration commands."""
    pass


@ci.command()
@click.option("--output", "-o", default=".github/workflows/codemind.yml", help="Output path for workflow file")
@click.option("--force", "-f", is_flag=True, help="Overwrite existing file")
def init(output: str, force: bool):
    """Generate GitHub Actions workflow for CodeMind.
    
    Creates a workflow file that runs CodeMind on every pull request.
    The workflow will analyze your code and generate review prompts.
    
    Examples:
      codemind ci init                              # Create default workflow
      codemind ci init -o .github/workflows/review.yml  # Custom path
    """
    terminal.print_header()
    
    from ...ci.github_action import generate_workflow_file
    
    output_path = Path.cwd() / output
    
    # Create parent directories
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    if output_path.exists() and not force:
        terminal.print_warning(f"File already exists: {output_path}")
        terminal.console.print("[dim]Use --force to overwrite.[/dim]")
        sys.exit(1)
    
    # Write workflow file
    workflow_content = generate_workflow_file()
    output_path.write_text(workflow_content, encoding="utf-8")
    
    terminal.print_success(f"Created workflow: {output_path}")
    terminal.console.print("\n[bold]Next steps:[/bold]")
    terminal.console.print("  1. Commit and push the workflow file")
    terminal.console.print("  2. Create a pull request")
    terminal.console.print("  3. CodeMind will run automatically on PRs")
    terminal.console.print("\n[dim]Workflow triggers on: pull_request (opened, synchronize, reopened)[/dim]")


@ci.command()
def info():
    """Show CI/CD integration information."""
    terminal.print_header()
    
    from ...ci.github_action import detect_ci_environment, get_pr_info
    
    env = detect_ci_environment()
    terminal.console.print(f"[bold]CI Environment:[/bold] {env.value}")
    
    pr_info = get_pr_info()
    if pr_info:
        terminal.console.print(f"\n[bold]Pull Request:[/bold]")
        terminal.console.print(f"  Number: #{pr_info.number}")
        terminal.console.print(f"  Title: {pr_info.title}")
        terminal.console.print(f"  Branch: {pr_info.head_branch} → {pr_info.base_branch}")
        terminal.console.print(f"  Author: {pr_info.author}")
