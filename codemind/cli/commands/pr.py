"""PR command module."""

import sys
import click
from pathlib import Path

from ..config import load_config
from ...git.diff import get_diff
from ...git.context import get_context
from ...ui import terminal
from ...llm import get_llm_provider


@click.group()
def pr():
    """Pull Request management commands."""
    pass


@pr.command()
@click.option("--base", "-b", default=None, help="Base branch (default: auto-detect)")
@click.option("--copy", "-c", is_flag=True, default=True, help="Copy to clipboard (default: true)")
def create(base, copy):
    """Generate a high-quality PR description from branch changes."""
    terminal.print_header()
    
    try:
        # Load config
        config = load_config()
        
        # Get context and diff
        context = get_context()
        diff = get_diff(base=base)
        
        if diff.is_empty:
            terminal.print_warning("No changes found between current branch and base.")
            sys.exit(0)
            
        terminal.print_info(f"Analyzing changes against {base or 'auto-detected base'}...")
        terminal.print_diff_summary(diff)
        
        # Load template
        template_path = Path(__file__).parent.parent.parent / "prompt" / "templates" / "pr.txt"
        template = template_path.read_text(encoding="utf-8")
        
        # Fill template
        prompt = template.replace("{{diff_content}}", diff.diff)
        prompt = prompt.replace("{{branch_name}}", context.current_branch)
        prompt = prompt.replace("{{files_list}}", ", ".join(f.path for f in diff.files))
        
        ai_response = None
        
        # Try Standalone LLM first if configured
        if config.llm.provider != "ide":
            with terminal.ui.spinner("Generating PR description...") as progress:
                progress.add_task(f"Using {config.llm.provider}", total=None)
                try:
                    llm = get_llm_provider(
                        provider_type=config.llm.provider,
                        model=config.llm.model,
                        api_key=config.llm.api_key,
                        base_url=config.llm.base_url
                    )
                    response = llm.generate(prompt)
                    ai_response = response.content
                except Exception as e:
                    terminal.print_error(f"LLM failed: {e}")
        
        if not ai_response:
            # Fallback to IDE prompt injection
            from ...ide.inject import copy_to_clipboard, inject_prompt, InjectionResult
            
            if config.ide.auto_inject:
                report = inject_prompt(prompt, auto_submit=config.ide.auto_submit)
                if report.result == InjectionResult.SUCCESS:
                    terminal.print_prompt_ready(report.ide.display_name)
                    terminal.print_info("Paste the generated PR description back here if you want to save it.")
                else:
                    copy_to_clipboard(prompt)
                    terminal.print_prompt_ready()
            else:
                copy_to_clipboard(prompt)
                terminal.print_prompt_ready()
                
            terminal.console.print("\n[yellow]PR generation prompted in IDE. Waiting for input...[/yellow]")
            terminal.console.print("[dim]Paste the AI response below (press Enter twice to finish):[/dim]\n")
            
            lines = []
            try:
                while True:
                    line = input()
                    if line == "" and lines and lines[-1] == "":
                        break
                    lines.append(line)
            except EOFError:
                pass
            ai_response = "\n".join(lines)

        if ai_response.strip():
            terminal.console.print("\n[bold cyan]━━━ Generated PR Description ━━━[/bold cyan]\n")
            terminal.console.print(ai_response)
            terminal.console.print("\n[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]\n")
            
            if copy:
                from ...ide.inject import copy_to_clipboard
                copy_to_clipboard(ai_response)
                terminal.print_success("PR description copied to clipboard!")
        else:
            terminal.print_warning("No PR description generated.")

    except Exception as e:
        terminal.print_error(f"PR creation failed: {e}")
        sys.exit(1)
