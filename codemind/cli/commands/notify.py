"""Notify command module."""

import sys
import click
from ...ui import terminal
from ...integration.notify import send_slack_notification, send_discord_notification
from ...history import get_recent_reviews


@click.group()
def notify():
    """Send notifications to external services."""
    pass


@notify.command()
@click.argument("webhook_url")
@click.option("--count", default=1, help="Number of recent reviews to include")
def slack(webhook_url, count):
    """Send latest review results to Slack."""
    terminal.print_header()
    terminal.print_info("Sending latest review results to Slack...")
    
    reviews = get_recent_reviews(count)
    if not reviews:
        terminal.print_warning("No recent reviews found to notify.")
        return
        
    for entry in reviews:
        message = (
            f"*Branch:* `{entry.branch}`\n"
            f"*Files Changed:* {entry.files_changed}\n"
            f"*Lines:* +{entry.lines_added} -{entry.lines_deleted}\n"
            f"*Status:* AI Review Completed ✅"
        )
        if send_slack_notification(webhook_url, message):
            terminal.print_success(f"Notification sent for branch: {entry.branch}")
        else:
            terminal.print_error(f"Failed to send notification for branch: {entry.branch}")


@notify.command()
@click.argument("webhook_url")
def discord(webhook_url):
    """Send latest review results to Discord."""
    terminal.print_header()
    terminal.print_info("Sending latest review results to Discord...")
    
    reviews = get_recent_reviews(1)
    if not reviews:
        terminal.print_warning("No recent reviews found.")
        return
        
    entry = reviews[0]
    message = f"**Branch:** `{entry.branch}`\n**Files Changed:** {entry.files_changed}\n**Status:** AI Review Ready"
    
    if send_discord_notification(webhook_url, message):
        terminal.print_success("Discord notification sent!")
    else:
        terminal.print_error("Failed to send Discord notification.")
