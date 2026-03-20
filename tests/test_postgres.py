from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dbgov.adapters.postgres import PostgresAdapter
from dbgov.models.grant import GrantSpec

if TYPE_CHECKING:
    from dbgov.settings.config import AppSettings

pytestmark = pytest.mark.usefixtures("pg_setup")


def _table_grant(
    principal: str = "test_user",
    tables: list[str] | None = None,
    privileges: list[str] | None = None,
) -> GrantSpec:
    return GrantSpec(
        db_principal=principal,
        principal_type="user",
        schema_name="public",
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
        schema_name="public",
        table_names=[],
        privileges=privileges or ["SELECT"],
        grant_level="schema",
    )


class TestPostgresConnection:
    def test_connect_and_test(self, pg_settings: AppSettings) -> None:
        adapter = PostgresAdapter(pg_settings)
        adapter.connect()
        assert adapter.test_connection()
        adapter.disconnect()

    def test_context_manager(self, pg_settings: AppSettings) -> None:
        with PostgresAdapter(pg_settings) as adapter:
            assert adapter.test_connection()


class TestPrincipalExists:
    def test_existing_principal(self, pg_settings: AppSettings) -> None:
        with PostgresAdapter(pg_settings) as adapter:
            assert adapter.principal_exists("test_user")

    def test_nonexistent_principal(self, pg_settings: AppSettings) -> None:
        with PostgresAdapter(pg_settings) as adapter:
            assert not adapter.principal_exists("no_such_user_xyz")


class TestGrant:
    def test_table_level_grant(self, pg_settings: AppSettings) -> None:
        with PostgresAdapter(pg_settings) as adapter:
            result = adapter.grant(_table_grant())
            assert result.success
            assert len(result.executed_sql) >= 2

            perms = adapter.list_permissions(schema="public", principal="test_user")
            matching = [p for p in perms if p.table_name == "orders" and p.privilege == "SELECT"]
            assert len(matching) == 1

    def test_multi_table_grant(self, pg_settings: AppSettings) -> None:
        with PostgresAdapter(pg_settings) as adapter:
            result = adapter.grant(_table_grant(tables=["orders", "customers"]))
            assert result.success

            perms = adapter.list_permissions(schema="public", principal="test_user")
            tables = {p.table_name for p in perms if p.privilege == "SELECT"}
            assert "orders" in tables
            assert "customers" in tables

    def test_multi_privilege_grant(self, pg_settings: AppSettings) -> None:
        with PostgresAdapter(pg_settings) as adapter:
            result = adapter.grant(_table_grant(privileges=["SELECT", "INSERT"]))
            assert result.success

            perms = adapter.list_permissions(schema="public", principal="test_user")
            privs = {p.privilege for p in perms if p.table_name == "orders"}
            assert "SELECT" in privs
            assert "INSERT" in privs

    def test_schema_level_grant(self, pg_settings: AppSettings) -> None:
        with PostgresAdapter(pg_settings) as adapter:
            result = adapter.grant(_schema_grant())
            assert result.success
            assert len(result.executed_sql) >= 3

            perms = adapter.list_permissions(schema="public", principal="test_user")
            assert len(perms) >= 1

    def test_grant_idempotent(self, pg_settings: AppSettings) -> None:
        spec = _table_grant()
        with PostgresAdapter(pg_settings) as adapter:
            r1 = adapter.grant(spec)
            r2 = adapter.grant(spec)
            assert r1.success
            assert r2.success

            perms = adapter.list_permissions(schema="public", principal="test_user")
            select_on_orders = [
                p for p in perms if p.table_name == "orders" and p.privilege == "SELECT"
            ]
            assert len(select_on_orders) == 1


class TestRevoke:
    def test_revoke_table_level(self, pg_settings: AppSettings) -> None:
        spec = _table_grant()
        with PostgresAdapter(pg_settings) as adapter:
            adapter.grant(spec)
            result = adapter.revoke(spec)
            assert result.success

            perms = adapter.list_permissions(schema="public", principal="test_user")
            matching = [p for p in perms if p.table_name == "orders" and p.privilege == "SELECT"]
            assert len(matching) == 0

    def test_revoke_schema_level(self, pg_settings: AppSettings) -> None:
        spec = _schema_grant()
        with PostgresAdapter(pg_settings) as adapter:
            adapter.grant(spec)
            result = adapter.revoke(spec)
            assert result.success

            perms = adapter.list_permissions(schema="public", principal="test_user")
            select_perms = [p for p in perms if p.privilege == "SELECT"]
            assert len(select_perms) == 0

    def test_revoke_idempotent(self, pg_settings: AppSettings) -> None:
        spec = _table_grant()
        with PostgresAdapter(pg_settings) as adapter:
            adapter.grant(spec)
            r1 = adapter.revoke(spec)
            r2 = adapter.revoke(spec)
            assert r1.success
            assert r2.success


class TestListPermissions:
    def test_empty_permissions(self, pg_settings: AppSettings) -> None:
        with PostgresAdapter(pg_settings) as adapter:
            perms = adapter.list_permissions(schema="public", principal="test_user")
            assert perms == []

    def test_filter_by_principal(self, pg_settings: AppSettings) -> None:
        with PostgresAdapter(pg_settings) as adapter:
            adapter.grant(_table_grant())
            perms = adapter.list_permissions(principal="test_user")
            assert all(p.principal == "test_user" for p in perms)

    def test_filter_by_schema(self, pg_settings: AppSettings) -> None:
        with PostgresAdapter(pg_settings) as adapter:
            adapter.grant(_table_grant())
            perms = adapter.list_permissions(schema="public")
            assert all(p.schema_name == "public" for p in perms)
