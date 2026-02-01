"""Slack and Discord notification integrations."""

import requests
from typing import Optional


def send_slack_notification(webhook_url: str, message: str, title: str = "CodeMind Review Result"):
    """Send a formatted notification to Slack."""
    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🧠 {title}",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": message
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "Sent via CodeMind AI Gateway 🏆"
                    }
                ]
            }
        ]
    }
    
    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        return True
    except Exception as e:
        print(f"Failed to send Slack notification: {e}")
        return False


def send_discord_notification(webhook_url: str, message: str, title: str = "CodeMind Review Result"):
    """Send a notification to Discord via webhook."""
    payload = {
        "content": f"**{title}**\n\n{message}\n\n*Sent via CodeMind AI Gateway*",
    }
    
    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        return True
    except Exception as e:
        print(f"Failed to send Discord notification: {e}")
        return False
