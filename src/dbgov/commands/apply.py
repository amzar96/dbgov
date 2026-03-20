from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

from dbgov.adapters.factory import get_adapter
from dbgov.logging import logger
from dbgov.parser.policy import parse_policy_file, parse_policy_glob

if TYPE_CHECKING:
    from dbgov.models.grant import GrantSpec
    from dbgov.settings.config import AppSettings


def run_apply(
    policy_path: str,
    settings: AppSettings,
) -> int:
    specs = _resolve_specs(policy_path)

    if not specs:
        logger.warning("No grant specs found in policy file(s)")
        return 0

    logger.info("Starting apply", engine=settings.engine, policy_path=policy_path)

    success_count = 0
    failed = False

    with get_adapter(settings) as adapter:
        if not adapter.test_connection():
            logger.error("Failed to connect to database")
            sys.exit(1)

        for spec in specs:
            if not adapter.principal_exists(spec.db_principal):
                logger.error(
                    "Principal does not exist in database",
                    principal=spec.db_principal,
                )
                sys.exit(1)

        for spec in specs:
            logger.info(
                "Granting privileges",
                privileges=spec.privileges,
                schema=spec.schema_name,
                principal=spec.db_principal,
            )
            result = adapter.grant(spec)

            if result.success:
                success_count += 1
                logger.info(
                    "Grant succeeded",
                    principal=spec.db_principal,
                    sql_count=len(result.executed_sql),
                )
            else:
                failed = True
                logger.error(
                    "Grant failed",
                    principal=spec.db_principal,
                    error=result.error,
                    succeeded_before_failure=success_count,
                )

    logger.info(
        "Apply summary",
        success=success_count,
        total=len(specs),
        failed=failed,
    )

    _set_github_output("grants_applied", str(success_count))

    if failed:
        sys.exit(1)

    return success_count


def _resolve_specs(policy_path: str) -> list[GrantSpec]:
    """Resolve policy path to grant specs — supports globs and space-separated file lists."""
    if "*" in policy_path or "?" in policy_path:
        return parse_policy_glob(policy_path)
    paths = policy_path.split()
    if len(paths) > 1:
        specs: list[GrantSpec] = []
        for p in paths:
            specs.extend(parse_policy_file(p))
        return specs
    return parse_policy_file(policy_path)


def _set_github_output(name: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        return
    with open(output_file, "a") as f:
        f.write(f"{name}={value}\n")
