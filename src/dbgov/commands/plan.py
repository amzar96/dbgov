from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

from dbgov.adapters.factory import get_adapter
from dbgov.logging import logger
from dbgov.models.grant import PlanRow
from dbgov.parser.policy import parse_policy_file, parse_policy_glob
from dbgov.reporter.pr_comment import post_pr_comment, should_post_comment

if TYPE_CHECKING:
    from dbgov.adapters.base import BaseAdapter
    from dbgov.models.grant import GrantSpec
    from dbgov.settings.config import AppSettings


def run_plan(
    policy_path: str,
    settings: AppSettings,
) -> str:
    if "*" in policy_path or "?" in policy_path:
        specs = parse_policy_glob(policy_path)
    else:
        specs = parse_policy_file(policy_path)

    if not specs:
        logger.warning("No grant specs found in policy file(s)")
        return ""

    logger.info("Starting plan", engine=settings.engine, policy_path=policy_path)

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

        plan_rows = _diff_permissions(adapter, specs)

    markdown = _format_plan_markdown(plan_rows)
    _log_plan_summary(plan_rows)

    if should_post_comment():
        post_pr_comment(markdown)

    _set_github_output("plan_summary", markdown)

    return markdown


def _diff_permissions(
    adapter: BaseAdapter,
    specs: list[GrantSpec],
) -> list[PlanRow]:
    rows: list[PlanRow] = []

    for spec in specs:
        current = adapter.list_permissions(
            schema=spec.schema_name,
            principal=spec.db_principal,
        )
        current_set = {
            (p.principal, p.schema_name, p.table_name, p.privilege.upper()) for p in current
        }

        if spec.grant_level == "table":
            for table in spec.table_names:
                for priv in spec.privileges:
                    key = (spec.db_principal, spec.schema_name, table, priv)
                    action = "NO-OP" if key in current_set else "GRANT"
                    rows.append(
                        PlanRow(
                            action=action,
                            principal=spec.db_principal,
                            schema_name=spec.schema_name,
                            table=table,
                            privilege=priv,
                        )
                    )
        else:
            table_label = "*" if spec.grant_level == "schema" else "*.*"
            for priv in spec.privileges:
                has_perm = any(
                    p.privilege.upper() == priv and p.principal == spec.db_principal
                    for p in current
                )
                action = "NO-OP" if has_perm else "GRANT"
                rows.append(
                    PlanRow(
                        action=action,
                        principal=spec.db_principal,
                        schema_name=spec.schema_name,
                        table=table_label,
                        privilege=priv,
                    )
                )

    return rows


def _format_plan_markdown(rows: list[PlanRow]) -> str:
    lines = [
        "## 🔐 DBGov Plan\n",
        "| Action | Principal | Schema | Table | Privilege |",
        "|--------|-----------|--------|-------|-----------|",
    ]
    for row in rows:
        icon = "✅" if row.action == "GRANT" else "➖"  # noqa: RUF001
        lines.append(
            f"| {icon} {row.action} | {row.principal} | {row.schema_name} "
            f"| {row.table} | {row.privilege} |"
        )

    grant_count = sum(1 for r in rows if r.action == "GRANT")
    noop_count = sum(1 for r in rows if r.action == "NO-OP")
    lines.append(f"\n**{grant_count} grant(s)** to apply, **{noop_count} no-op(s)**.")
    lines.append("\nReady to apply on merge.")

    return "\n".join(lines)


def _log_plan_summary(rows: list[PlanRow]) -> None:
    grant_count = sum(1 for r in rows if r.action == "GRANT")
    noop_count = sum(1 for r in rows if r.action == "NO-OP")

    for row in rows:
        logger.info(
            "Plan row",
            action=row.action,
            principal=row.principal,
            schema=row.schema_name,
            table=row.table,
            privilege=row.privilege,
        )

    logger.info("Plan summary", grants=grant_count, noops=noop_count, total=len(rows))


def _set_github_output(name: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        return
    with open(output_file, "a") as f:
        delimiter = "EOF_DBGOV"
        f.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")
