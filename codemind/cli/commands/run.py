"""Run command module."""

import sys
from pathlib import Path
from typing import Optional

import click

from ...ui import terminal
from ...ide.inject import inject_prompt, InjectionResult
from ...history import save_review
from ...llm import get_llm_provider
from ..config import load_config
from ...git.diff import get_diff, DiffExtractor
from ...git.context import get_context
from ...prompt.builder import build_prompt, PromptConfig
from ...ide.detect import IDEType, IDE_TYPE_MAP


@click.command()
@click.option("--hook", is_flag=True, hidden=True, help="Called from git hook")
@click.option("--base", "-b", default=None, help="Base ref for diff (default: auto-detect)")
@click.option("--no-inject", is_flag=True, help="Don't auto-inject, just copy to clipboard")
@click.option("--dry-run", is_flag=True, help="Show what would happen without injecting")
@click.option("--preview", is_flag=True, help="Show the prompt before injecting")
@click.option("--interactive", "-i", is_flag=True, help="Interactive mode for reviewing AI feedback")
@click.option("--vibe", is_flag=True, help="Enable 'Vibecoding' mode (encouraging, high-performance focus)")
def run(hook: bool, base: Optional[str], no_inject: bool, dry_run: bool, preview: bool, interactive: bool, vibe: bool):
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
        
        if vibe:
            template_path = Path(__file__).parent.parent.parent / "prompt" / "templates" / "vibe.txt"
        elif config.prompt.template_path:
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
            # Show a bit more if it's large but not everything to avoid flooding
            terminal.console.print(built_prompt.content[:2000])
            if len(built_prompt.content) > 2000:
                terminal.console.print(f"\n[dim]... ({len(built_prompt.content) - 2000} more chars)[/dim]")
            terminal.console.print("\n[bold cyan]━━━━━━━━━━━━━━━━━━━━━[/bold cyan]\n")
            terminal.console.print(f"[dim]Token estimate: ~{built_prompt.token_estimate}[/dim]")
        
        # Dry-run mode: exit before injection
        if dry_run:
            terminal.print_info("Dry run complete. No prompt was injected.")
            sys.exit(0)
        
        # Inject or copy or direct LLM run
        ai_response = None
        
        if config.llm.provider != "ide":
            # Standalone LLM Mode
            with terminal.ui.spinner(f"Running review via {config.llm.provider}...") as progress:
                progress.add_task(f"Generating review using {config.llm.model or 'default'} model", total=None)
                try:
                    llm = get_llm_provider(
                        provider_type=config.llm.provider,
                        model=config.llm.model,
                        api_key=config.llm.api_key,
                        base_url=config.llm.base_url
                    )
                    response = llm.generate(built_prompt.content)
                    ai_response = response.content
                    terminal.print_success(f"Review completed via {config.llm.provider}")
                except Exception as e:
                    terminal.print_error(f"Standalone LLM failed: {e}")
                    terminal.print_info("Falling back to IDE/Clipboard...")
        
        if ai_response:
            # We already have the response from standalone LLM
            terminal.console.print("\n[bold cyan]━━━ AI Review Feedback ━━━[/bold cyan]\n")
            terminal.console.print(ai_response)
            terminal.console.print("\n[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]\n")
        elif no_inject or not config.ide.auto_inject:
            # Just copy to clipboard
            from ...ide.inject import copy_to_clipboard
            copy_to_clipboard(built_prompt.content)
            terminal.print_prompt_ready()
        else:
            # Auto-inject (will detect running IDE)
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
        
        # Interactive mode: parse AI response and review issues
        if interactive:
            from ...interactive.session import InteractiveSession
            
            if not ai_response:
                terminal.console.print("\n[bold]Paste the AI review response below, then press Enter twice:[/bold]\n")
                
                # Collect multi-line input
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
                session = InteractiveSession()
                session.add_issues_from_text(ai_response)
                
                if session.issues:
                    proceed = session.run_interactive()
                    
                    if proceed and session.critical_count == 0:
                        terminal.print_push_continuing()
                        sys.exit(0)
                    else:
                        terminal.print_push_aborted()
                        terminal.console.print(f"[dim]{session.critical_count} critical issues remain.[/dim]")
                        sys.exit(1)
                else:
                    terminal.print_success("No issues found in AI response!")
                    terminal.print_push_continuing()
                    sys.exit(0)
            else:
                terminal.print_warning("No AI response provided.")
        
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
