"""MCP command module."""

import click
from ...ui import terminal


@click.command()
@click.option("--transport", type=click.Choice(["stdio", "streamable-http"]), default="stdio", help="Transport type")
@click.option("--host", default="localhost", help="HTTP host")
@click.option("--port", default=8000, help="HTTP port")
def serve(transport: str, host: str, port: int):
    """Run CodeMind as an MCP server.
    
    This exposes CodeMind functionality via the Model Context Protocol (MCP),
    allowing AI clients to use CodeMind tools for code review.
    
    Tools available:
      - review_diff: Generate review prompt for git changes
      - validate_ai_response: Validate AI review output
      - get_review_history: Get recent reviews
      - get_git_context: Get git repository info
    """
    terminal.print_header()
    terminal.print_info(f"Starting MCP server with {transport} transport...")
    
    try:
        from ...mcp.server import run_mcp_server
        run_mcp_server(transport=transport, host=host, port=port)
    except Exception as e:
        terminal.print_error(f"Failed to start MCP server: {e}")
        # If mcp is not installed, provide helpful message
        try:
            import mcp # noqa
        except ImportError:
            terminal.console.print("\n[bold]Hint:[/bold] Install MCP support with: [cyan]pip install codemind[mcp][/cyan]")
