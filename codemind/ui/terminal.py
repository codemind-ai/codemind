"""Terminal UI module.

Professional terminal output for CodeMind.
"""

import sys
import os
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

from ..git.diff import DiffResult


# Global console instance
console = Console()


def _get_tty_input(prompt: str = "", default: str = "") -> str:
    """Get input from TTY even when stdin is redirected (git hooks)."""
    # Try to read from /dev/tty (Unix) or CON (Windows)
    tty_path = "CON" if sys.platform == "win32" else "/dev/tty"
    
    try:
        with open(tty_path, "r") as tty:
            console.print(prompt, end="")
            return tty.readline().strip() or default
    except (FileNotFoundError, OSError):
        # Fallback to regular input if TTY not available
        try:
            return input(prompt) or default
        except EOFError:
            return default


def _confirm_tty(prompt: str, default: bool = True) -> bool:
    """Confirm from TTY even when stdin is redirected."""
    default_str = "Y/n" if default else "y/N"
    full_prompt = f"{prompt} [{default_str}]: "
    
    response = _get_tty_input(full_prompt).lower().strip()
    
    if not response:
        return default
    
    return response in ("y", "yes", "true", "1")


class TerminalUI:
    """Terminal UI for CodeMind."""
    
    def __init__(self):
        self.console = console
    
    def print_header(self) -> None:
        """Print the CodeMind header."""
        self.console.print()
        self.console.print(
            "[bold cyan]🧠 CodeMind[/bold cyan] [dim]— Think before ship.[/dim]"
        )
        self.console.print("[dim]────────────────────────────────────────────────────[/dim]")
    
    def print_diff_summary(self, diff: DiffResult) -> None:
        """Print a summary of the diff."""
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        table.add_column("Label", style="dim cyan")
        table.add_column("Value", style="bold white")
        
        table.add_row("Files changed", str(diff.total_files))
        table.add_row(
            "Lines",
            f"[bold green]+{diff.total_additions}[/bold green]  [bold red]-{diff.total_deletions}[/bold red]"
        )
        
        if diff.files:
            file_list = ", ".join(f.path for f in diff.files[:5])
            if len(diff.files) > 5:
                file_list += f" [dim](+{len(diff.files) - 5} more)[/dim]"
            table.add_row("Files", file_list)
        
        self.console.print(
            Panel(
                table, 
                title="[bold blue]📊 Diff Summary[/bold blue]", 
                border_style="cyan",
                padding=(1, 2)
            )
        )
    
    def ask_review(self) -> str:
        """
        Ask user if they want to run a review.
        """
        self.console.print(
            "\n[bold white]Ready to run AI review?[/bold white]"
        )
        self.console.print(
            "[dim]  [y] Yes   [n] No   [a] Always   [s] Skip once[/dim]"
        )
        
        while True:
            choice = Prompt.ask(
                "[bold cyan]Choice[/bold cyan]",
                default="y",
                show_default=True
            ).lower().strip()
            
            if choice in ['y', 'n', 'a', 's', 'yes', 'no', 'always', 'skip']:
                return choice[0]
            
            self.console.print("[red]Invalid choice. Use y/n/a/s[/red]")
    
    def print_prompt_ready(self, ide_name: Optional[str] = None) -> None:
        """Print message that prompt is ready."""
        if ide_name:
            self.console.print(
                f"\n[bold green]✅ Success![/bold green] Prompt injected into [bold cyan]{ide_name}[/bold cyan]"
            )
            self.console.print("[dim]Check your IDE chat to review the AI feedback.[/dim]")
        else:
            self.console.print(
                "\n[bold yellow]📋 Ready![/bold yellow] Prompt copied to clipboard"
            )
            self.console.print(
                "[dim]Paste into your IDE AI chat and run the review.[/dim]"
            )
    
    def wait_for_review(self) -> None:
        """Wait for user to complete the AI review."""
        self.console.print()
        try:
            Prompt.ask(
                "[bold white]Press ENTER when AI review is complete[/bold white]",
                default=""
            )
        except Exception:
            _get_tty_input("Press ENTER when AI review is complete: ")
    
    def print_warning(self, message: str) -> None:
        """Print a warning message."""
        self.console.print(f"[bold yellow]⚠️  {message}[/bold yellow]")
    
    def print_error(self, message: str) -> None:
        """Print an error message."""
        self.console.print(f"[bold red]❌ {message}[/bold red]")
    
    def print_success(self, message: str) -> None:
        """Print a success message."""
        self.console.print(f"[bold green]✨ {message}[/bold green]")
    
    def print_info(self, message: str) -> None:
        """Print an info message."""
        self.console.print(f"[bold blue]ℹ️  {message}[/bold blue]")
    
    def confirm_push(self) -> bool:
        """Ask user to confirm the push."""
        try:
            return Confirm.ask(
                "\n[bold white]Does the review look good? Proceed with push?[/bold white]",
                default=True
            )
        except Exception:
            return _confirm_tty("Proceed with push?", default=True)
    
    def print_push_aborted(self) -> None:
        """Print message that push was aborted."""
        self.console.print(
            "\n[bold red]🛑 Push Aborted.[/bold red] [dim]Fix issues and try again.[/dim]"
        )
    
    def print_push_continuing(self) -> None:
        """Print message that push is continuing."""
        self.console.print("\n[bold green]🚀 Launching...[/bold green] [dim](Pushing to remote)[/dim]")
    
    def spinner(self, message: str):
        """Get a spinner context manager."""
        return Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold cyan]{task.description}"),
            console=self.console,
            transient=True
        )


# Global UI instance
ui = TerminalUI()


def print_header() -> None:
    ui.print_header()

def print_diff_summary(diff: DiffResult) -> None:
    ui.print_diff_summary(diff)

def ask_review() -> str:
    return ui.ask_review()

def print_prompt_ready(ide_name: Optional[str] = None) -> None:
    ui.print_prompt_ready(ide_name)

def wait_for_review() -> None:
    ui.wait_for_review()

def print_warning(message: str) -> None:
    ui.print_warning(message)

def print_error(message: str) -> None:
    ui.print_error(message)

def print_success(message: str) -> None:
    ui.print_success(message)

def print_info(message: str) -> None:
    ui.print_info(message)

def confirm_push() -> bool:
    return ui.confirm_push()

def print_push_aborted() -> None:
    ui.print_push_aborted()

def print_push_continuing() -> None:
    ui.print_push_continuing()



