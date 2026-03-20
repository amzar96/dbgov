from __future__ import annotations

from typing import TYPE_CHECKING, Any

import redshift_connector  # type: ignore[import-untyped]

from dbgov.adapters.base import BaseAdapter
from dbgov.logging import logger
from dbgov.models.grant import AdapterResult, GrantSpec, PermissionRecord

if TYPE_CHECKING:
    from dbgov.settings.config import AppSettings


def _qi(identifier: str) -> str:
    sanitized = identifier.replace('"', '""')
    return f'"{sanitized}"'


def _log_sql(sql: str) -> None:
    logger.info("Executed SQL", sql=sql)


class RedshiftAdapter(BaseAdapter):
    def __init__(self, settings: AppSettings) -> None:
        super().__init__(settings)
        self._conn: Any = None

    def connect(self) -> None:
        self._conn = redshift_connector.connect(
            host=self.settings.host,
            port=self.settings.port,
            database=self.settings.name,
            user=self.settings.user,
            password=self.settings.password,
        )
        self._conn.autocommit = True

    def disconnect(self) -> None:
        if self._conn:
            self._conn.close()

    def test_connection(self) -> bool:
        try:
            with self._conn.cursor() as cur:
                cur.execute("SELECT 1")
            return True
        except Exception:
            return False

    def principal_exists(self, db_principal: str) -> bool:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM pg_user WHERE usename = %s "
                "UNION SELECT 1 FROM pg_group WHERE groname = %s",
                (db_principal, db_principal),
            )
            return cur.fetchone() is not None

    def grant(self, spec: GrantSpec) -> AdapterResult:
        sql_statements: list[str] = []
        try:
            with self._conn.cursor() as cur:
                usage_sql = (
                    f"GRANT USAGE ON SCHEMA {_qi(spec.schema_name)} TO {_qi(spec.db_principal)}"
                )
                cur.execute(usage_sql)
                sql_statements.append(usage_sql)
                _log_sql(usage_sql)

                if spec.grant_level == "schema":
                    sql_statements.extend(self._grant_schema_level(cur, spec))
                elif spec.grant_level == "database":
                    sql_statements.extend(self._grant_database_level(cur, spec))
                else:
                    sql_statements.extend(self._grant_table_level(cur, spec))

            return AdapterResult(success=True, executed_sql=sql_statements)
        except Exception as exc:
            return AdapterResult(success=False, executed_sql=sql_statements, error=str(exc))

    def _grant_table_level(self, cur: Any, spec: GrantSpec) -> list[str]:
        executed: list[str] = []
        privs = ", ".join(spec.privileges)
        for table in spec.table_names:
            sql = (
                f"GRANT {privs} ON {_qi(spec.schema_name)}.{_qi(table)} TO {_qi(spec.db_principal)}"
            )
            cur.execute(sql)
            executed.append(sql)
            _log_sql(sql)
        return executed

    def _grant_schema_level(self, cur: Any, spec: GrantSpec) -> list[str]:
        executed: list[str] = []
        privs = ", ".join(spec.privileges)

        sql = (
            f"GRANT {privs} ON ALL TABLES IN SCHEMA {_qi(spec.schema_name)} "
            f"TO {_qi(spec.db_principal)}"
        )
        cur.execute(sql)
        executed.append(sql)
        _log_sql(sql)

        sql = (
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA {_qi(spec.schema_name)} "
            f"GRANT {privs} ON TABLES TO {_qi(spec.db_principal)}"
        )
        cur.execute(sql)
        executed.append(sql)
        _log_sql(sql)

        logger.warning(
            "Redshift caveat: ALTER DEFAULT PRIVILEGES only applies to tables "
            "created by the current user",
            schema=spec.schema_name,
            principal=spec.db_principal,
        )

        return executed

    def _grant_database_level(self, cur: Any, spec: GrantSpec) -> list[str]:
        executed: list[str] = []
        cur.execute(
            "SELECT schema_name FROM information_schema.schemata "
            "WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'pg_toast')"
        )
        schemas = [row[0] for row in cur.fetchall()]
        for schema in schemas:
            schema_spec = GrantSpec(
                db_principal=spec.db_principal,
                principal_type=spec.principal_type,
                schema_name=schema,
                table_names=[],
                privileges=list(spec.privileges),
                grant_level="schema",
                expires_at=spec.expires_at,
            )
            usage_sql = f"GRANT USAGE ON SCHEMA {_qi(schema)} TO {_qi(spec.db_principal)}"
            cur.execute(usage_sql)
            executed.append(usage_sql)
            _log_sql(usage_sql)

            executed.extend(self._grant_schema_level(cur, schema_spec))
        return executed

    def revoke(self, spec: GrantSpec) -> AdapterResult:
        sql_statements: list[str] = []
        try:
            with self._conn.cursor() as cur:
                if spec.grant_level == "schema":
                    sql_statements.extend(self._revoke_schema_level(cur, spec))
                elif spec.grant_level == "database":
                    sql_statements.extend(self._revoke_database_level(cur, spec))
                else:
                    sql_statements.extend(self._revoke_table_level(cur, spec))

            return AdapterResult(success=True, executed_sql=sql_statements)
        except Exception as exc:
            return AdapterResult(success=False, executed_sql=sql_statements, error=str(exc))

    def _revoke_table_level(self, cur: Any, spec: GrantSpec) -> list[str]:
        executed: list[str] = []
        privs = ", ".join(spec.privileges)
        for table in spec.table_names:
            sql = (
                f"REVOKE {privs} ON {_qi(spec.schema_name)}.{_qi(table)} "
                f"FROM {_qi(spec.db_principal)}"
            )
            cur.execute(sql)
            executed.append(sql)
            _log_sql(sql)
        return executed

    def _revoke_schema_level(self, cur: Any, spec: GrantSpec) -> list[str]:
        executed: list[str] = []
        privs = ", ".join(spec.privileges)

        sql = (
            f"REVOKE {privs} ON ALL TABLES IN SCHEMA {_qi(spec.schema_name)} "
            f"FROM {_qi(spec.db_principal)}"
        )
        cur.execute(sql)
        executed.append(sql)
        _log_sql(sql)

        sql = (
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA {_qi(spec.schema_name)} "
            f"REVOKE {privs} ON TABLES FROM {_qi(spec.db_principal)}"
        )
        cur.execute(sql)
        executed.append(sql)
        _log_sql(sql)

        return executed

    def _revoke_database_level(self, cur: Any, spec: GrantSpec) -> list[str]:
        executed: list[str] = []
        cur.execute(
            "SELECT schema_name FROM information_schema.schemata "
            "WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'pg_toast')"
        )
        schemas = [row[0] for row in cur.fetchall()]
        for schema in schemas:
            schema_spec = GrantSpec(
                db_principal=spec.db_principal,
                principal_type=spec.principal_type,
                schema_name=schema,
                table_names=[],
                privileges=list(spec.privileges),
                grant_level="schema",
                expires_at=spec.expires_at,
            )
            executed.extend(self._revoke_schema_level(cur, schema_spec))
        return executed

    def list_permissions(
        self,
        schema: str | None = None,
        principal: str | None = None,
    ) -> list[PermissionRecord]:
        query = (
            "SELECT identity_name, namespace_name, relation_name, privilege_type "
            "FROM svv_relation_privileges WHERE 1=1"
        )
        params: list[str] = []

        if schema:
            query += " AND namespace_name = %s"
            params.append(schema)
        if principal:
            query += " AND identity_name = %s"
            params.append(principal)

        with self._conn.cursor() as cur:
            cur.execute(query, params)
            return [
                PermissionRecord(
                    principal=row[0],
                    schema_name=row[1],
                    table_name=row[2],
                    privilege=row[3],
                )
                for row in cur.fetchall()
            ]
