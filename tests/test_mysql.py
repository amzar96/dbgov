from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dbgov.adapters.mysql import MySQLAdapter
from dbgov.models.grant import GrantSpec

if TYPE_CHECKING:
    from dbgov.settings.config import AppSettings

pytestmark = pytest.mark.usefixtures("_mysql_ready")


def _table_grant(
    principal: str = "test_user",
    tables: list[str] | None = None,
    privileges: list[str] | None = None,
) -> GrantSpec:
    return GrantSpec(
        db_principal=principal,
        principal_type="user",
        schema_name="dbgov_test",
        table_names=tables or ["orders"],
        privileges=privileges or ["SELECT"],
        grant_level="table",
    )


def _schema_grant(
    principal: str = "test_user",
    privileges: list[str] | None = None,
) -> GrantSpec:
    return GrantSpec(
        db_principal=principal,
        principal_type="user",
        schema_name="dbgov_test",
        table_names=[],
        privileges=privileges or ["SELECT"],
        grant_level="schema",
    )


class TestMySQLConnection:
    def test_connect_and_test(self, mysql_settings: AppSettings) -> None:
        adapter = MySQLAdapter(mysql_settings)
        adapter.connect()
        assert adapter.test_connection()
        adapter.disconnect()

    def test_context_manager(self, mysql_settings: AppSettings) -> None:
        with MySQLAdapter(mysql_settings) as adapter:
            assert adapter.test_connection()


class TestPrincipalExists:
    def test_existing_principal(self, mysql_settings: AppSettings, mysql_conn: object) -> None:
        with MySQLAdapter(mysql_settings) as adapter:
            assert adapter.principal_exists("test_user")

    def test_nonexistent_principal(self, mysql_settings: AppSettings, mysql_conn: object) -> None:
        with MySQLAdapter(mysql_settings) as adapter:
            assert not adapter.principal_exists("no_such_user_xyz")


class TestGrant:
    def test_table_level_grant(self, mysql_settings: AppSettings, mysql_conn: object) -> None:
        with MySQLAdapter(mysql_settings) as adapter:
            result = adapter.grant(_table_grant())
            assert result.success
            assert len(result.executed_sql) >= 1

            perms = adapter.list_permissions(schema="dbgov_test", principal="test_user")
            matching = [p for p in perms if p.table_name == "orders" and p.privilege == "SELECT"]
            assert len(matching) == 1

    def test_multi_table_grant(self, mysql_settings: AppSettings, mysql_conn: object) -> None:
        with MySQLAdapter(mysql_settings) as adapter:
            result = adapter.grant(_table_grant(tables=["orders", "customers"]))
            assert result.success

            perms = adapter.list_permissions(schema="dbgov_test", principal="test_user")
            tables = {p.table_name for p in perms if p.privilege == "SELECT"}
            assert "orders" in tables
            assert "customers" in tables

    def test_multi_privilege_grant(self, mysql_settings: AppSettings, mysql_conn: object) -> None:
        with MySQLAdapter(mysql_settings) as adapter:
            result = adapter.grant(_table_grant(privileges=["SELECT", "INSERT"]))
            assert result.success

            perms = adapter.list_permissions(schema="dbgov_test", principal="test_user")
            privs = {p.privilege for p in perms if p.table_name == "orders"}
            assert "SELECT" in privs
            assert "INSERT" in privs

    def test_schema_level_grant(self, mysql_settings: AppSettings, mysql_conn: object) -> None:
        with MySQLAdapter(mysql_settings) as adapter:
            result = adapter.grant(_schema_grant())
            assert result.success
            assert len(result.executed_sql) >= 1

    def test_grant_idempotent(self, mysql_settings: AppSettings, mysql_conn: object) -> None:
        spec = _table_grant()
        with MySQLAdapter(mysql_settings) as adapter:
            r1 = adapter.grant(spec)
            r2 = adapter.grant(spec)
            assert r1.success
            assert r2.success


class TestRevoke:
    def test_revoke_table_level(self, mysql_settings: AppSettings, mysql_conn: object) -> None:
        spec = _table_grant()
        with MySQLAdapter(mysql_settings) as adapter:
            adapter.grant(spec)
            result = adapter.revoke(spec)
            assert result.success

            perms = adapter.list_permissions(schema="dbgov_test", principal="test_user")
            matching = [p for p in perms if p.table_name == "orders" and p.privilege == "SELECT"]
            assert len(matching) == 0

    def test_revoke_schema_level(self, mysql_settings: AppSettings, mysql_conn: object) -> None:
        spec = _schema_grant()
        with MySQLAdapter(mysql_settings) as adapter:
            adapter.grant(spec)
            result = adapter.revoke(spec)
            assert result.success


class TestListPermissions:
    def test_filter_by_principal(self, mysql_settings: AppSettings, mysql_conn: object) -> None:
        with MySQLAdapter(mysql_settings) as adapter:
            adapter.grant(_table_grant())
            perms = adapter.list_permissions(principal="test_user")
            assert all(p.principal == "test_user" for p in perms)

    def test_filter_by_schema(self, mysql_settings: AppSettings, mysql_conn: object) -> None:
        with MySQLAdapter(mysql_settings) as adapter:
            adapter.grant(_table_grant())
            perms = adapter.list_permissions(schema="dbgov_test")
            assert all(p.schema_name == "dbgov_test" for p in perms)
