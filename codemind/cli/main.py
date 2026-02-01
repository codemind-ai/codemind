"""codemind AI - Main CLI entrypoint.

Think before ship. Standardized AI code reviews and commit messages.

🏆 Vibeathon 2025 Entry
"""

import sys
import click

from .. import __version__
from .commands.run import run
from .commands.config import config
from .commands.rules import rules
from .commands.ci import ci
from .commands.commit import commit
from .commands.history import history
from .commands.template import template
from .commands.info import detect, status
from .commands.mcp import serve
from .commands.hooks import install, uninstall


@click.group()
@click.version_option(version=__version__, prog_name="codemind AI")
def cli():
    """🚀 codemind AI - Pre-push AI code review orchestrator.
    
    CodeMind brings structure and consistency to AI code reviews by
    orchestrating your local IDE's AI before you push code.
    """
    pass


# Add commands from sub-modules
cli.add_command(run)
cli.add_command(config)
cli.add_command(rules)
cli.add_command(ci)
cli.add_command(commit)
cli.add_command(history)
cli.add_command(template)
cli.add_command(status)
cli.add_command(detect)
cli.add_command(serve)
cli.add_command(install)
cli.add_command(uninstall)


def main():
    """Main entry point."""
    try:
        cli()
    except Exception as e:
        from ..ui import terminal
        terminal.print_error(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
