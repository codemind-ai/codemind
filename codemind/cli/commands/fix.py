"""Fix command module."""

import sys
import click
import shutil
from pathlib import Path

from ..config import load_config
from ...history import get_recent_reviews
from ...validate.parser import parse_review
from ...ui import terminal
from ...llm import get_llm_provider
from ...llm.fixer import CodeFixer


@click.command()
@click.option("--latest", "-l", is_flag=True, help="Fix issues from the latest review")
@click.option("--auto-apply", "-y", is_flag=True, help="Automatically apply fixes without confirmation")
def fix(latest, auto_apply):
    """Automatically fix issues identified in previous reviews."""
    terminal.print_header()
    
    try:
        # Load config
        config = load_config()
        
        # Get latest review with AI response
        reviews = get_recent_reviews(10)
        review_to_fix = None
        
        for r in reversed(reviews):
            if r.ai_response:
                review_to_fix = r
                break
        
        if not review_to_fix:
            terminal.print_error("No previous reviews with AI feedback found. Run 'codemind run' first.")
            sys.exit(1)
            
        terminal.print_info(f"Analyzing issues from review on branch: [bold]{review_to_fix.branch}[/bold] ({review_to_fix.timestamp[:16]})")
        
        # Parse review
        parsed = parse_review(review_to_fix.ai_response)
        
        if parsed.is_clean:
            terminal.print_success("No issues to fix in the last review!")
            sys.exit(0)
            
        # Group issues by file
        files_to_fix = {}
        for issue in parsed.issues:
            if issue.file_path:
                if issue.file_path not in files_to_fix:
                    files_to_fix[issue.file_path] = []
                files_to_fix[issue.file_path].append(issue.message)
        
        if not files_to_fix:
            terminal.print_warning("Could not identify specific files to fix from the AI response.")
            sys.exit(0)
            
        # Initialize LLM for fixing
        try:
            llm = get_llm_provider(
                provider_type=config.llm.provider,
                model=config.llm.model,
                api_key=config.llm.api_key,
                base_url=config.llm.base_url
            )
            fixer = CodeFixer(llm)
        except Exception as e:
            terminal.print_error(f"Failed to initialize LLM for fixing: {e}")
            sys.exit(1)
            
        # Process each file
        for file_path, issues in files_to_fix.items():
            full_path = Path(file_path)
            if not full_path.exists():
                terminal.print_warning(f"File not found: {file_path}. Skipping.")
                continue
                
            terminal.console.print(f"\n[bold cyan]🔧 Fixing {file_path}...[/bold cyan]")
            for issue in issues:
                terminal.console.print(f"  • {issue}")
            
            # Read current content
            current_content = full_path.read_text(encoding="utf-8")
            
            # Generate fix
            with terminal.ui.spinner("Generating fix...") as progress:
                progress.add_task("AI is thinking...", total=None)
                fixed_content = fixer.generate_fix(file_path, current_content, "\n".join(issues))
            
            if fixed_content.strip() == current_content.strip():
                terminal.print_info(f"AI suggests no changes needed for {file_path}.")
                continue
                
            # Show diff
            terminal.ui.print_diff(current_content, fixed_content, file_path)
            
            if not auto_apply:
                choice = click.prompt(
                    f"Apply changes to {file_path}?",
                    type=click.Choice(['y', 'n']),
                    default='y'
                )
                
                if choice == 'n':
                    terminal.print_info(f"Skipping {file_path}.")
                    continue
            
            # Backup before overwrite
            backup_path = full_path.with_suffix(full_path.suffix + ".orig")
            shutil.copy2(full_path, backup_path)
            
            # Write back
            full_path.write_text(fixed_content, encoding="utf-8")
            terminal.print_success(f"Applied fix to {file_path} (Backup: {backup_path.name})")
            
        terminal.print_success("\n✨ All fixes processed!")
        
    except Exception as e:
        terminal.print_error(f"Fix failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
