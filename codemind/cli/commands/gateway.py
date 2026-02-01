"""Gateway command module."""

import sys
import click
import uvicorn
from ...ui import terminal


@click.group()
def gateway():
    """Manage the CodeMind REST API Gateway."""
    pass


@gateway.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", default=8000, help="Port to listen on")
@click.option("--reload", is_flag=True, help="Enable auto-reload (development only)")
def start(host, port, reload):
    """Start the CodeMind REST API server."""
    terminal.print_header()
    terminal.print_info(f"Starting CodeMind API Gateway on {host}:{port}...")
    
    try:
        uvicorn.run(
            "codemind.api.server:app",
            host=host,
            port=port,
            reload=reload,
            log_level="info"
        )
    except Exception as e:
        terminal.print_error(f"Gateway failed to start: {e}")
        sys.exit(1)
