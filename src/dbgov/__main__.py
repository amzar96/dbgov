from __future__ import annotations

import sys

import typer

from dbgov.commands.apply import run_apply
from dbgov.commands.plan import run_plan
from dbgov.logging import logger
from dbgov.settings.config import AppSettings

app = typer.Typer(
    name="dbgov",
    help="Database Access Governance — manage DB permissions as code.",
    no_args_is_help=True,
)


@app.command()
def plan(
    file: str = typer.Option(
        "./policies/*.yaml",
        "--file",
        "-f",
        help="Path to policy YAML file or glob pattern.",
    ),
) -> None:
    """Dry run — show what grants will change without applying."""
    try:
        run_plan(policy_path=file, settings=AppSettings())  # type: ignore[call-arg]
    except Exception as exc:
        logger.error("Plan failed", error=str(exc))
        sys.exit(1)


@app.command()
def apply(
    file: str = typer.Option(
        "./policies/*.yaml",
        "--file",
        "-f",
        help="Path to policy YAML file or glob pattern.",
    ),
) -> None:
    """Execute grants from policy file(s)."""
    try:
        count = run_apply(policy_path=file, settings=AppSettings())  # type: ignore[call-arg]
        logger.info("Apply completed", grants_applied=count)
    except Exception as exc:
        logger.error("Apply failed", error=str(exc))
        sys.exit(1)


if __name__ == "__main__":
    app()
