"""History command module."""

import click
from ...history import get_recent_reviews, get_review_stats, clear_history
from ...ui import terminal


@click.command()
@click.option("--list", "show_list", is_flag=True, help="List recent reviews")
@click.option("--stats", is_flag=True, help="Show statistics")
@click.option("--clear", is_flag=True, help="Clear review history")
@click.option("--count", "-n", default=10, help="Number of entries to show")
def history(show_list: bool, stats: bool, clear: bool, count: int):
    """View review history and statistics."""
    terminal.print_header()
    
    if clear:
        if click.confirm("[red]Are you sure you want to clear all review history?[/red]"):
            clear_history()
            terminal.print_success("History cleared.")
            return

    if stats or (not show_list and not clear):
        review_stats = get_review_stats()
        terminal.console.print("\n[bold]📊 Review Statistics[/bold]\n")
        terminal.console.print(f"  Total reviews: [cyan]{review_stats['total_reviews']}[/cyan]")
        terminal.console.print(f"  Files analyzed: [cyan]{review_stats['total_files']}[/cyan]")
        terminal.console.print(f"  Lines added: [green]+{review_stats['total_lines_added']}[/green]")
        terminal.console.print(f"  Lines deleted: [red]-{review_stats['total_lines_deleted']}[/red]")
        terminal.console.print(f"  Reviews today: [cyan]{review_stats['reviews_today']}[/cyan]")
        
        if not show_list:
            terminal.console.print("\n[dim]Use --list to see recent entries.[/dim]")

    if show_list:
        reviews = get_recent_reviews(count)
        if not reviews:
            terminal.print_info("No review history found.")
            return
            
        terminal.console.print(f"\n[bold]📜 Recent Reviews (last {len(reviews)})[/bold]\n")
        for r in reviews:
            date_str = r.timestamp.strftime("%Y-%m-%d %H:%M")
            terminal.console.print(f"  [dim]{date_str}[/dim] | [cyan]{r.branch}[/cyan] | [green]+{r.lines_added}[/green] [red]-{r.lines_deleted}[/red]")
            terminal.console.print(f"     [dim]{', '.join(r.files[:3])}{'...' if len(r.files) > 3 else ''}[/dim]")
            terminal.console.print()
