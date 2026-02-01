"""Interactive review session module.

Provides a rich TUI for reviewing AI feedback interactively.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich import box


class IssueSeverity(Enum):
    """Issue severity levels."""
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    SUGGESTION = "suggestion"


@dataclass
class ReviewIssue:
    """Represents a single review issue."""
    severity: IssueSeverity
    message: str
    file: Optional[str] = None
    line: Optional[int] = None
    suggestion: Optional[str] = None
    resolved: bool = False
    
    @property
    def severity_icon(self) -> str:
        """Get icon for severity."""
        icons = {
            IssueSeverity.CRITICAL: "🚨",
            IssueSeverity.WARNING: "⚠️",
            IssueSeverity.INFO: "ℹ️",
            IssueSeverity.SUGGESTION: "💡",
        }
        return icons.get(self.severity, "•")
    
    @property
    def severity_color(self) -> str:
        """Get color for severity."""
        colors = {
            IssueSeverity.CRITICAL: "red",
            IssueSeverity.WARNING: "yellow",
            IssueSeverity.INFO: "blue",
            IssueSeverity.SUGGESTION: "cyan",
        }
        return colors.get(self.severity, "white")


@dataclass
class InteractiveSession:
    """Interactive review session with keyboard navigation."""
    
    issues: list[ReviewIssue] = field(default_factory=list)
    current_index: int = 0
    console: Console = field(default_factory=Console)
    
    # Callbacks
    on_resolve: Optional[Callable[[ReviewIssue], None]] = None
    on_skip: Optional[Callable[[ReviewIssue], None]] = None
    
    def add_issue(self, issue: ReviewIssue) -> None:
        """Add an issue to the session."""
        self.issues.append(issue)
    
    def add_issues_from_text(self, text: str) -> None:
        """Parse issues from AI response text."""
        lines = text.strip().split('\n')
        current_severity = IssueSeverity.INFO
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Detect section headers
            if "critical" in line.lower() or "🚨" in line:
                current_severity = IssueSeverity.CRITICAL
                continue
            elif "warning" in line.lower() or "⚠️" in line or "issue" in line.lower():
                current_severity = IssueSeverity.WARNING
                continue
            elif "suggestion" in line.lower() or "💡" in line:
                current_severity = IssueSeverity.SUGGESTION
                continue
            elif "info" in line.lower() or "ℹ️" in line:
                current_severity = IssueSeverity.INFO
                continue
            
            # Parse issue line
            if line.startswith("-") or line.startswith("•") or line.startswith("*"):
                message = line.lstrip("-•* ").strip()
                if message and message.lower() != "none":
                    # Try to extract file and line info
                    file_info = None
                    line_num = None
                    
                    # Look for file:line pattern
                    import re
                    file_match = re.search(r'`?(\w+\.py)`?\s*(?:line|L)?\s*(\d+)?', message)
                    if file_match:
                        file_info = file_match.group(1)
                        if file_match.group(2):
                            line_num = int(file_match.group(2))
                    
                    self.add_issue(ReviewIssue(
                        severity=current_severity,
                        message=message,
                        file=file_info,
                        line=line_num,
                    ))
    
    @property
    def current_issue(self) -> Optional[ReviewIssue]:
        """Get currently selected issue."""
        if not self.issues or self.current_index >= len(self.issues):
            return None
        return self.issues[self.current_index]
    
    @property
    def unresolved_count(self) -> int:
        """Count of unresolved issues."""
        return sum(1 for i in self.issues if not i.resolved)
    
    @property
    def critical_count(self) -> int:
        """Count of critical issues."""
        return sum(1 for i in self.issues 
                   if i.severity == IssueSeverity.CRITICAL and not i.resolved)
    
    def next_issue(self) -> None:
        """Move to next issue."""
        if self.current_index < len(self.issues) - 1:
            self.current_index += 1
    
    def prev_issue(self) -> None:
        """Move to previous issue."""
        if self.current_index > 0:
            self.current_index -= 1
    
    def resolve_current(self) -> None:
        """Mark current issue as resolved."""
        if self.current_issue:
            self.current_issue.resolved = True
            if self.on_resolve:
                self.on_resolve(self.current_issue)
    
    def skip_current(self) -> None:
        """Skip current issue."""
        if self.current_issue and self.on_skip:
            self.on_skip(self.current_issue)
        self.next_issue()
    
    def render_issues_list(self) -> Table:
        """Render the issues list as a table."""
        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold",
            expand=True,
        )
        
        table.add_column("#", style="dim", width=3)
        table.add_column("", width=3)  # Icon
        table.add_column("Issue", ratio=3)
        table.add_column("File", style="cyan", ratio=1)
        table.add_column("Status", width=8)
        
        for idx, issue in enumerate(self.issues):
            is_current = idx == self.current_index
            
            # Build row style
            row_style = ""
            if is_current:
                row_style = "reverse"
            elif issue.resolved:
                row_style = "dim"
            
            # Status indicator
            status = "✓" if issue.resolved else ""
            if is_current and not issue.resolved:
                status = "→"
            
            # Truncate message
            msg = issue.message[:60] + "..." if len(issue.message) > 60 else issue.message
            
            table.add_row(
                str(idx + 1),
                issue.severity_icon,
                msg,
                issue.file or "-",
                status,
                style=row_style,
            )
        
        return table
    
    def render_current_detail(self) -> Panel:
        """Render detailed view of current issue."""
        issue = self.current_issue
        
        if not issue:
            return Panel("No issues to review!", title="Details")
        
        content = Text()
        content.append(f"{issue.severity_icon} ", style="bold")
        content.append(f"{issue.severity.value.upper()}\n\n", style=f"bold {issue.severity_color}")
        content.append(issue.message + "\n\n", style="white")
        
        if issue.file:
            content.append("File: ", style="dim")
            content.append(f"{issue.file}", style="cyan")
            if issue.line:
                content.append(f":{issue.line}", style="cyan")
            content.append("\n")
        
        if issue.suggestion:
            content.append("\nSuggestion: ", style="bold blue")
            content.append(issue.suggestion, style="blue")
        
        return Panel(
            content,
            title=f"[bold]Issue {self.current_index + 1} of {len(self.issues)}[/bold]",
            border_style=issue.severity_color,
        )
    
    def render_help(self) -> Text:
        """Render keyboard shortcuts help."""
        help_text = Text()
        help_text.append("  ↑/k", style="bold cyan")
        help_text.append(" prev  ", style="dim")
        help_text.append("↓/j", style="bold cyan")
        help_text.append(" next  ", style="dim")
        help_text.append("Enter", style="bold green")
        help_text.append(" resolve  ", style="dim")
        help_text.append("s", style="bold yellow")
        help_text.append(" skip  ", style="dim")
        help_text.append("q", style="bold red")
        help_text.append(" quit", style="dim")
        return help_text
    
    def render_summary(self) -> Text:
        """Render session summary."""
        summary = Text()
        summary.append(f"Total: {len(self.issues)}  ", style="dim")
        
        if self.critical_count > 0:
            summary.append(f"🚨 {self.critical_count}  ", style="red")
        
        resolved = len(self.issues) - self.unresolved_count
        summary.append(f"✓ {resolved}/{len(self.issues)} resolved", style="green")
        
        return summary
    
    def run_interactive(self) -> bool:
        """
        Run the interactive session.
        
        Returns:
            True if user wants to proceed with push
            False if user wants to abort
        """
        if not self.issues:
            self.console.print("[green]✓[/green] No issues found!")
            return True
        
        # Print header
        self.console.print("\n[bold blue]CodeMind[/bold blue] — Interactive Review\n")
        self.console.print(self.render_summary())
        self.console.print()
        self.console.print(self.render_issues_list())
        self.console.print()
        self.console.print(self.render_current_detail())
        self.console.print()
        self.console.print(self.render_help())
        self.console.print()
        
        # Simple input loop (non-blocking version would require curses/blessed)
        while True:
            try:
                key = input("\nAction [j/k/Enter/s/q]: ").strip().lower()
                
                if key in ('q', 'quit', 'exit'):
                    return False
                elif key in ('j', 'down', ''):
                    self.next_issue()
                elif key in ('k', 'up'):
                    self.prev_issue()
                elif key in ('enter', 'r', 'resolve', ''):
                    self.resolve_current()
                    self.next_issue()
                elif key in ('s', 'skip'):
                    self.skip_current()
                
                # Re-render
                self.console.clear()
                self.console.print("\n[bold blue]CodeMind[/bold blue] — Interactive Review\n")
                self.console.print(self.render_summary())
                self.console.print()
                self.console.print(self.render_issues_list())
                self.console.print()
                self.console.print(self.render_current_detail())
                self.console.print()
                self.console.print(self.render_help())
                
                # Check if all done
                if self.unresolved_count == 0:
                    self.console.print("\n[bold green]✓ All issues resolved![/bold green]")
                    return True
                    
            except KeyboardInterrupt:
                self.console.print("\n\n[yellow]Cancelled.[/yellow]")
                return False
            except EOFError:
                return False
    
    def get_summary_result(self) -> dict:
        """Get a summary of the session results."""
        return {
            "total_issues": len(self.issues),
            "resolved": len(self.issues) - self.unresolved_count,
            "unresolved": self.unresolved_count,
            "critical_unresolved": self.critical_count,
            "should_proceed": self.critical_count == 0,
        }
