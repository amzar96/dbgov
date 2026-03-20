from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pymysql  # type: ignore[import-untyped]

from dbgov.adapters.base import BaseAdapter
from dbgov.logging import logger
from dbgov.models.grant import AdapterResult, CreatePrincipalSpec, GrantSpec, PermissionRecord

if TYPE_CHECKING:
    from dbgov.settings.config import AppSettings


class MySQLAdapter(BaseAdapter):
    def __init__(self, settings: AppSettings) -> None:
        super().__init__(settings)
        self._conn: Any = None

    def connect(self) -> None:
        self._conn = pymysql.connect(
            host=self.settings.host,
            port=self.settings.port,
            database=self.settings.name,
            user=self.settings.user,
            password=self.settings.password,
            autocommit=True,
        )

    def disconnect(self) -> None:
        if self._conn and self._conn.open:
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
                "SELECT 1 FROM mysql.user WHERE User = %s",
                (db_principal,),
            )
            return cur.fetchone() is not None

    def create_principal(self, spec: CreatePrincipalSpec) -> AdapterResult:
        sql_statements: list[str] = []
        try:
            if self.principal_exists(spec.name):
                logger.info("Principal already exists, skipping", principal=spec.name)
                return AdapterResult(success=True, executed_sql=[])

            with self._conn.cursor() as cur:
                if spec.password:
                    sql = f"CREATE USER '{_qs(spec.name)}'@'%' IDENTIFIED BY %s"
                    cur.execute(sql, (spec.password,))
                    log_msg = f"CREATE USER '{spec.name}'@'%' IDENTIFIED BY '***'"
                else:
                    sql = f"CREATE ROLE '{_qs(spec.name)}'"
                    cur.execute(sql)
                    log_msg = sql

                sql_statements.append(log_msg)
                _log_sql(log_msg)

            return AdapterResult(success=True, executed_sql=sql_statements)
        except Exception as exc:
            return AdapterResult(success=False, executed_sql=sql_statements, error=str(exc))

    def grant(self, spec: GrantSpec) -> AdapterResult:
        sql_statements: list[str] = []
        try:
            with self._conn.cursor() as cur:
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
                f"GRANT {privs} ON {_qi(spec.schema_name)}.{_qi(table)} "
                f"TO '{_qs(spec.db_principal)}'@'%'"
            )
            cur.execute(sql)
            executed.append(sql)
            _log_sql(sql)
        return executed

    def _grant_schema_level(self, cur: Any, spec: GrantSpec) -> list[str]:
        executed: list[str] = []
        privs = ", ".join(spec.privileges)
        sql = f"GRANT {privs} ON {_qi(spec.schema_name)}.* TO '{_qs(spec.db_principal)}'@'%'"
        cur.execute(sql)
        executed.append(sql)
        _log_sql(sql)
        return executed

    def _grant_database_level(self, cur: Any, spec: GrantSpec) -> list[str]:
        executed: list[str] = []
        privs = ", ".join(spec.privileges)
        sql = f"GRANT {privs} ON *.* TO '{_qs(spec.db_principal)}'@'%'"
        cur.execute(sql)
        executed.append(sql)
        _log_sql(sql)
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
                f"FROM '{_qs(spec.db_principal)}'@'%'"
            )
            cur.execute(sql)
            executed.append(sql)
            _log_sql(sql)
        return executed

    def _revoke_schema_level(self, cur: Any, spec: GrantSpec) -> list[str]:
        executed: list[str] = []
        privs = ", ".join(spec.privileges)
        sql = f"REVOKE {privs} ON {_qi(spec.schema_name)}.* FROM '{_qs(spec.db_principal)}'@'%'"
        cur.execute(sql)
        executed.append(sql)
        _log_sql(sql)
        return executed

    def _revoke_database_level(self, cur: Any, spec: GrantSpec) -> list[str]:
        executed: list[str] = []
        privs = ", ".join(spec.privileges)
        sql = f"REVOKE {privs} ON *.* FROM '{_qs(spec.db_principal)}'@'%'"
        cur.execute(sql)
        executed.append(sql)
        _log_sql(sql)
        return executed

    def list_permissions(
        self,
        schema: str | None = None,
        principal: str | None = None,
    ) -> list[PermissionRecord]:
        query = (
            "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE "
            "FROM information_schema.TABLE_PRIVILEGES WHERE 1=1"
        )
        params: list[str] = []

        if schema:
            query += " AND TABLE_SCHEMA = %s"
            params.append(schema)
        if principal:
            query += " AND GRANTEE LIKE %s"
            params.append(f"'{principal}'@%")

        with self._conn.cursor() as cur:
            cur.execute(query, params)
            return [
                PermissionRecord(
                    principal=_extract_user(row[0]),
                    schema_name=row[1],
                    table_name=row[2],
                    privilege=row[3],
                )
                for row in cur.fetchall()
            ]


def _qi(identifier: str) -> str:
    sanitized = identifier.replace("`", "``")
    return f"`{sanitized}`"


def _qs(value: str) -> str:
    return value.replace("'", "''")


def _extract_user(grantee: str) -> str:
    if grantee.startswith("'") and "@" in grantee:
        return grantee.split("'")[1]
    return grantee


def _log_sql(sql: str) -> None:
    logger.info("Executed SQL", sql=sql)
