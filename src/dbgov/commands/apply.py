from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

from dbgov.adapters.factory import get_adapter
from dbgov.logging import logger
from dbgov.parser.policy import ParsedPolicies, parse_file, parse_glob

if TYPE_CHECKING:
    from dbgov.settings.config import AppSettings


def run_apply(
    policy_path: str,
    settings: AppSettings,
) -> int:
    parsed = _resolve_policies(policy_path)

    if not parsed.grants and not parsed.principals:
        logger.warning("No specs found in policy file(s)")
        return 0

    logger.info("Starting apply", engine=settings.engine, policy_path=policy_path)

    failed = False
    principal_count = 0
    grant_count = 0

    with get_adapter(settings) as adapter:
        if not adapter.test_connection():
            logger.error("Failed to connect to database")
            sys.exit(1)

        # Step 1: Create principals first
        for spec in parsed.principals:
            logger.info("Creating principal", name=spec.name, type=spec.type)
            result = adapter.create_principal(spec)
            if result.success:
                principal_count += 1
                logger.info("Principal ready", name=spec.name, sql_count=len(result.executed_sql))
            else:
                failed = True
                logger.error("Principal creation failed", name=spec.name, error=result.error)

        if failed:
            logger.error("Aborting apply due to principal creation failure")
            sys.exit(1)

        # Step 2: Verify all grant principals exist
        for spec in parsed.grants:
            if not adapter.principal_exists(spec.db_principal):
                logger.error(
                    "Principal does not exist in database",
                    principal=spec.db_principal,
                )
                sys.exit(1)

        # Step 3: Apply grants
        for spec in parsed.grants:
            logger.info(
                "Granting privileges",
                privileges=spec.privileges,
                schema=spec.schema_name,
                principal=spec.db_principal,
            )
            result = adapter.grant(spec)

            if result.success:
                grant_count += 1
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
                    succeeded_before_failure=grant_count,
                )

    logger.info(
        "Apply summary",
        principals_created=principal_count,
        grants_applied=grant_count,
        total_grants=len(parsed.grants),
        failed=failed,
    )

    _set_github_output("principals_created", str(principal_count))
    _set_github_output("grants_applied", str(grant_count))

    if failed:
        sys.exit(1)

    return grant_count


def _resolve_policies(policy_path: str) -> ParsedPolicies:
    """Resolve policy path — supports globs and space-separated file lists."""
    if "*" in policy_path or "?" in policy_path:
        return parse_glob(policy_path)
    paths = policy_path.split()
    if len(paths) > 1:
        result = ParsedPolicies()
        for p in paths:
            parsed = parse_file(p)
            result.principals.extend(parsed.principals)
            result.grants.extend(parsed.grants)
        return result
    return parse_file(policy_path)


def _set_github_output(name: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        return
    with open(output_file, "a") as f:
        f.write(f"{name}={value}\n")
