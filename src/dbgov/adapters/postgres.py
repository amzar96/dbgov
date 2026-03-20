from __future__ import annotations

from typing import TYPE_CHECKING

import psycopg
from psycopg.sql import SQL, Identifier

from dbgov.adapters.base import BaseAdapter
from dbgov.logging import logger
from dbgov.models.grant import AdapterResult, GrantSpec, PermissionRecord

if TYPE_CHECKING:
    from dbgov.settings.config import AppSettings


class PostgresAdapter(BaseAdapter):
    def __init__(self, settings: AppSettings) -> None:
        super().__init__(settings)
        self._conn: psycopg.Connection | None = None

    def connect(self) -> None:
        kwargs: dict[str, str | int | bool] = {
            "host": self.settings.host,
            "port": self.settings.port,
            "dbname": self.settings.name,
            "user": self.settings.user,
            "password": self.settings.password,
            "autocommit": True,
        }
        if self.settings.options:
            kwargs["options"] = self.settings.options
        self._conn = psycopg.connect(**kwargs)

    def disconnect(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()

    def test_connection(self) -> bool:
        try:
            assert self._conn
            self._conn.execute("SELECT 1")
            return True
        except Exception:
            return False

    def principal_exists(self, db_principal: str) -> bool:
        assert self._conn
        row = self._conn.execute(
            "SELECT 1 FROM pg_roles WHERE rolname = %s",
            (db_principal,),
        ).fetchone()
        return row is not None

    def grant(self, spec: GrantSpec) -> AdapterResult:
        sql_statements: list[str] = []
        try:
            assert self._conn
            usage_sql = SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                Identifier(spec.schema_name), Identifier(spec.db_principal)
            )
            self._conn.execute(usage_sql)
            rendered = usage_sql.as_string(self._conn)
            sql_statements.append(rendered)
            _log_sql(rendered)

            if spec.grant_level == "schema":
                sql_statements.extend(self._grant_schema_level(spec))
            elif spec.grant_level == "database":
                sql_statements.extend(self._grant_database_level(spec))
            else:
                sql_statements.extend(self._grant_table_level(spec))

            return AdapterResult(success=True, executed_sql=sql_statements)
        except Exception as exc:
            return AdapterResult(success=False, executed_sql=sql_statements, error=str(exc))

    def _grant_table_level(self, spec: GrantSpec) -> list[str]:
        assert self._conn
        executed: list[str] = []
        privs = SQL(", ").join(SQL(p) for p in spec.privileges)
        for table in spec.table_names:
            stmt = SQL("GRANT {} ON {}.{} TO {}").format(
                privs,
                Identifier(spec.schema_name),
                Identifier(table),
                Identifier(spec.db_principal),
            )
            self._conn.execute(stmt)
            rendered = stmt.as_string(self._conn)
            executed.append(rendered)
            _log_sql(rendered)
        return executed

    def _grant_schema_level(self, spec: GrantSpec) -> list[str]:
        assert self._conn
        executed: list[str] = []
        privs = SQL(", ").join(SQL(p) for p in spec.privileges)

        stmt = SQL("GRANT {} ON ALL TABLES IN SCHEMA {} TO {}").format(
            privs, Identifier(spec.schema_name), Identifier(spec.db_principal)
        )
        self._conn.execute(stmt)
        rendered = stmt.as_string(self._conn)
        executed.append(rendered)
        _log_sql(rendered)

        stmt = SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA {} GRANT {} ON TABLES TO {}").format(
            Identifier(spec.schema_name), privs, Identifier(spec.db_principal)
        )
        self._conn.execute(stmt)
        rendered = stmt.as_string(self._conn)
        executed.append(rendered)
        _log_sql(rendered)

        return executed

    def _grant_database_level(self, spec: GrantSpec) -> list[str]:
        assert self._conn
        executed: list[str] = []
        rows = self._conn.execute(
            "SELECT schema_name FROM information_schema.schemata "
            "WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'pg_toast')"
        ).fetchall()
        for (schema,) in rows:
            schema_spec = GrantSpec(
                db_principal=spec.db_principal,
                principal_type=spec.principal_type,
                schema_name=schema,
                table_names=[],
                privileges=list(spec.privileges),
                grant_level="schema",
                expires_at=spec.expires_at,
            )
            usage_stmt = SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                Identifier(schema), Identifier(spec.db_principal)
            )
            self._conn.execute(usage_stmt)
            rendered = usage_stmt.as_string(self._conn)
            executed.append(rendered)
            _log_sql(rendered)

            executed.extend(self._grant_schema_level(schema_spec))
        return executed

    def revoke(self, spec: GrantSpec) -> AdapterResult:
        sql_statements: list[str] = []
        try:
            assert self._conn
            if spec.grant_level == "schema":
                sql_statements.extend(self._revoke_schema_level(spec))
            elif spec.grant_level == "database":
                sql_statements.extend(self._revoke_database_level(spec))
            else:
                sql_statements.extend(self._revoke_table_level(spec))

            return AdapterResult(success=True, executed_sql=sql_statements)
        except Exception as exc:
            return AdapterResult(success=False, executed_sql=sql_statements, error=str(exc))

    def _revoke_table_level(self, spec: GrantSpec) -> list[str]:
        assert self._conn
        executed: list[str] = []
        privs = SQL(", ").join(SQL(p) for p in spec.privileges)
        for table in spec.table_names:
            stmt = SQL("REVOKE {} ON {}.{} FROM {}").format(
                privs,
                Identifier(spec.schema_name),
                Identifier(table),
                Identifier(spec.db_principal),
            )
            self._conn.execute(stmt)
            rendered = stmt.as_string(self._conn)
            executed.append(rendered)
            _log_sql(rendered)
        return executed

    def _revoke_schema_level(self, spec: GrantSpec) -> list[str]:
        assert self._conn
        executed: list[str] = []
        privs = SQL(", ").join(SQL(p) for p in spec.privileges)

        stmt = SQL("REVOKE {} ON ALL TABLES IN SCHEMA {} FROM {}").format(
            privs, Identifier(spec.schema_name), Identifier(spec.db_principal)
        )
        self._conn.execute(stmt)
        rendered = stmt.as_string(self._conn)
        executed.append(rendered)
        _log_sql(rendered)

        stmt = SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA {} REVOKE {} ON TABLES FROM {}").format(
            Identifier(spec.schema_name), privs, Identifier(spec.db_principal)
        )
        self._conn.execute(stmt)
        rendered = stmt.as_string(self._conn)
        executed.append(rendered)
        _log_sql(rendered)

        return executed

    def _revoke_database_level(self, spec: GrantSpec) -> list[str]:
        assert self._conn
        executed: list[str] = []
        rows = self._conn.execute(
            "SELECT schema_name FROM information_schema.schemata "
            "WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'pg_toast')"
        ).fetchall()
        for (schema,) in rows:
            schema_spec = GrantSpec(
                db_principal=spec.db_principal,
                principal_type=spec.principal_type,
                schema_name=schema,
                table_names=[],
                privileges=list(spec.privileges),
                grant_level="schema",
                expires_at=spec.expires_at,
            )
            executed.extend(self._revoke_schema_level(schema_spec))
        return executed

    def list_permissions(
        self,
        schema: str | None = None,
        principal: str | None = None,
    ) -> list[PermissionRecord]:
        assert self._conn
        query = (
            "SELECT grantee, table_schema, table_name, privilege_type "
            "FROM information_schema.role_table_grants "
            "WHERE grantor = current_user"
        )
        params: list[str] = []

        if schema:
            query += " AND table_schema = %s"
            params.append(schema)
        if principal:
            query += " AND grantee = %s"
            params.append(principal)

        rows = self._conn.execute(query, params).fetchall()
        return [
            PermissionRecord(
                principal=row[0],
                schema_name=row[1],
                table_name=row[2],
                privilege=row[3],
            )
            for row in rows
        ]


def _log_sql(sql: str) -> None:
    logger.info("Executed SQL", sql=sql)
