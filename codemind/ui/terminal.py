"""Terminal UI module.

Professional terminal output for CodeMind.
"""

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


class TerminalUI:
    """Terminal UI for CodeMind."""
    
    def __init__(self):
        self.console = console
    
    def print_header(self) -> None:
        """Print the CodeMind header."""
        self.console.print()
        self.console.print(
            "[bold blue]CodeMind[/bold blue] [dim]— Pre-push code review[/dim]"
        )
        self.console.print()
    
    def print_diff_summary(self, diff: DiffResult) -> None:
        """Print a summary of the diff."""
        table = Table(box=box.ROUNDED, show_header=False, padding=(0, 1))
        table.add_column("Label", style="dim")
        table.add_column("Value", style="bold")
        
        table.add_row("Files", str(diff.total_files))
        table.add_row(
            "Lines",
            f"[green]+{diff.total_additions}[/green] / [red]-{diff.total_deletions}[/red]"
        )
        
        if diff.files:
            file_list = ", ".join(f.path for f in diff.files[:5])
            if len(diff.files) > 5:
                file_list += f" [dim](+{len(diff.files) - 5} more)[/dim]"
            table.add_row("Changed", file_list)
        
        self.console.print(Panel(table, title="Changes Detected", border_style="blue"))
    
    def ask_review(self) -> str:
        """
        Ask user if they want to run a review.
        
        Returns:
            'y' (yes), 'n' (no), 'a' (always), 's' (skip once)
        """
        self.console.print(
            "\n[bold]Run AI review before push?[/bold]"
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
                f"\n[green]>[/green] Prompt injected into [bold]{ide_name}[/bold]"
            )
        else:
            self.console.print(
                "\n[yellow]>[/yellow] Prompt copied to clipboard"
            )
            self.console.print(
                "[dim]Paste into your IDE AI chat and run the review.[/dim]"
            )
    
    def wait_for_review(self) -> None:
        """Wait for user to complete the AI review."""
        self.console.print()
        Prompt.ask(
            "[bold]Press ENTER when AI review is complete[/bold]",
            default=""
        )
    
    def print_warning(self, message: str) -> None:
        """Print a warning message."""
        self.console.print(f"[yellow]! {message}[/yellow]")
    
    def print_error(self, message: str) -> None:
        """Print an error message."""
        self.console.print(f"[red]x {message}[/red]")
    
    def print_success(self, message: str) -> None:
        """Print a success message."""
        self.console.print(f"[green]> {message}[/green]")
    
    def print_info(self, message: str) -> None:
        """Print an info message."""
        self.console.print(f"[blue]i {message}[/blue]")
    
    def confirm_push(self) -> bool:
        """Ask user to confirm the push."""
        return Confirm.ask(
            "\n[bold]Proceed with push?[/bold]",
            default=True
        )
    
    def print_push_aborted(self) -> None:
        """Print message that push was aborted."""
        self.console.print(
            "\n[yellow]Aborted.[/yellow] "
            "[dim]Fix issues and try again.[/dim]"
        )
    
    def print_push_continuing(self) -> None:
        """Print message that push is continuing."""
        self.console.print("\n[green]> Pushing...[/green]")
    
    def spinner(self, message: str):
        """Get a spinner context manager."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
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
