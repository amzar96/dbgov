"""End-to-end CLI tests against docker-compose databases.

These tests invoke the CLI via typer.testing.CliRunner and verify
the full flow: CLI → parser → adapter → database.

Assertions are based on exit codes and database state, since loguru
writes to real stderr which CliRunner cannot capture.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from dbgov.__main__ import app

if TYPE_CHECKING:
    from collections.abc import Generator

    import psycopg

    from dbgov.settings.config import AppSettings

FIXTURES = Path(__file__).parent / "fixtures"
PRINCIPAL = "analyst_user"

runner = CliRunner()


# ── helpers ──────────────────────────────────────────────────────────────


def _env_for(settings: AppSettings, **extra: str) -> dict[str, str]:
    """Build DBGOV_* env vars from settings."""
    env = {
        "DBGOV_ENGINE": settings.engine,
        "DBGOV_HOST": settings.host,
        "DBGOV_PORT": str(settings.port),
        "DBGOV_NAME": settings.name,
        "DBGOV_USER": settings.user,
        "DBGOV_PASSWORD": settings.password,
    }
    env.update(extra)
    return env


def _principal_exists(conn: psycopg.Connection, name: str) -> bool:
    row = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (name,)).fetchone()
    return row is not None


def _grant_count(conn: psycopg.Connection, principal: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM information_schema.role_table_grants "
        "WHERE grantee = %s AND privilege_type = 'SELECT'",
        (principal,),
    ).fetchone()
    return row[0] if row else 0


def _pg_cleanup_user(conn: psycopg.Connection) -> None:
    with contextlib.suppress(Exception):
        conn.execute(f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {PRINCIPAL}")
        conn.execute(
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM {PRINCIPAL}"
        )
        conn.execute(f"REVOKE USAGE ON SCHEMA public FROM {PRINCIPAL}")
        conn.execute(f"REASSIGN OWNED BY {PRINCIPAL} TO dbgov")
        conn.execute(f"DROP OWNED BY {PRINCIPAL}")
        conn.execute(f"DROP ROLE IF EXISTS {PRINCIPAL}")


# ── fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture()
def pg_e2e(pg_conn: psycopg.Connection) -> Generator[None, None, None]:
    """Set up tables for CLI e2e tests, clean up after."""
    _pg_cleanup_user(pg_conn)
    pg_conn.execute("CREATE TABLE IF NOT EXISTS public.transactions (id int)")
    pg_conn.execute("CREATE TABLE IF NOT EXISTS public.accounts (id int)")

    yield

    _pg_cleanup_user(pg_conn)
    pg_conn.execute("DROP TABLE IF EXISTS public.transactions")
    pg_conn.execute("DROP TABLE IF EXISTS public.accounts")


# ── Postgres Plan ────────────────────────────────────────────────────────


class TestPostgresPlan:
    pytestmark = pytest.mark.usefixtures("pg_e2e")

    def test_plan_succeeds_with_existing_principal(
        self, pg_conn: psycopg.Connection, pg_settings: AppSettings
    ) -> None:
        pg_conn.execute(f"CREATE ROLE {PRINCIPAL} LOGIN")
        env = _env_for(pg_settings)
        result = runner.invoke(
            app, ["plan", "--file", str(FIXTURES / "analyst-finance.yaml")], env=env
        )
        assert result.exit_code == 0

    def test_plan_succeeds_after_apply(
        self, pg_conn: psycopg.Connection, pg_settings: AppSettings
    ) -> None:
        """Plan should still succeed (NO-OP) after grants applied."""
        pg_conn.execute(f"CREATE ROLE {PRINCIPAL} LOGIN")
        env = _env_for(pg_settings)

        runner.invoke(app, ["apply", "--file", str(FIXTURES / "analyst-finance.yaml")], env=env)
        result = runner.invoke(
            app, ["plan", "--file", str(FIXTURES / "analyst-finance.yaml")], env=env
        )
        assert result.exit_code == 0

    def test_plan_succeeds_even_without_principal(self, pg_settings: AppSettings) -> None:
        """Plan should still succeed for missing principal — it shows GRANT actions."""
        env = _env_for(pg_settings)
        result = runner.invoke(
            app, ["plan", "--file", str(FIXTURES / "analyst-finance.yaml")], env=env
        )
        assert result.exit_code == 0


# ── Postgres Apply ───────────────────────────────────────────────────────


class TestPostgresApply:
    pytestmark = pytest.mark.usefixtures("pg_e2e")

    def test_apply_grants_permissions(
        self, pg_conn: psycopg.Connection, pg_settings: AppSettings
    ) -> None:
        pg_conn.execute(f"CREATE ROLE {PRINCIPAL} LOGIN")
        env = _env_for(pg_settings)
        result = runner.invoke(
            app, ["apply", "--file", str(FIXTURES / "analyst-finance.yaml")], env=env
        )
        assert result.exit_code == 0
        assert _grant_count(pg_conn, PRINCIPAL) >= 2

    def test_apply_idempotent(self, pg_conn: psycopg.Connection, pg_settings: AppSettings) -> None:
        pg_conn.execute(f"CREATE ROLE {PRINCIPAL} LOGIN")
        env = _env_for(pg_settings)
        fixture = str(FIXTURES / "analyst-finance.yaml")

        result1 = runner.invoke(app, ["apply", "--file", fixture], env=env)
        assert result1.exit_code == 0
        count1 = _grant_count(pg_conn, PRINCIPAL)

        result2 = runner.invoke(app, ["apply", "--file", fixture], env=env)
        assert result2.exit_code == 0
        count2 = _grant_count(pg_conn, PRINCIPAL)

        assert count1 == count2

    def test_apply_fails_for_missing_principal(self, pg_settings: AppSettings) -> None:
        env = _env_for(pg_settings)
        result = runner.invoke(
            app, ["apply", "--file", str(FIXTURES / "analyst-finance.yaml")], env=env
        )
        assert result.exit_code != 0


# ── Postgres Principal Creation ──────────────────────────────────────────


class TestPostgresPrincipalCreation:
    pytestmark = pytest.mark.usefixtures("pg_e2e")

    def test_apply_creates_principal(
        self, pg_conn: psycopg.Connection, pg_settings: AppSettings
    ) -> None:
        env = _env_for(pg_settings, TEST_USER_PASSWORD="secret123")
        result = runner.invoke(
            app, ["apply", "--file", str(FIXTURES / "principal-analyst.yaml")], env=env
        )
        assert result.exit_code == 0
        assert _principal_exists(pg_conn, PRINCIPAL)

    def test_apply_principal_idempotent(
        self, pg_conn: psycopg.Connection, pg_settings: AppSettings
    ) -> None:
        env = _env_for(pg_settings, TEST_USER_PASSWORD="secret123")
        fixture = str(FIXTURES / "principal-analyst.yaml")

        result1 = runner.invoke(app, ["apply", "--file", fixture], env=env)
        assert result1.exit_code == 0

        result2 = runner.invoke(app, ["apply", "--file", fixture], env=env)
        assert result2.exit_code == 0

    def test_plan_succeeds_for_new_principal(self, pg_settings: AppSettings) -> None:
        env = _env_for(pg_settings, TEST_USER_PASSWORD="secret123")
        result = runner.invoke(
            app, ["plan", "--file", str(FIXTURES / "principal-analyst.yaml")], env=env
        )
        assert result.exit_code == 0

    def test_plan_succeeds_for_existing_principal(
        self, pg_conn: psycopg.Connection, pg_settings: AppSettings
    ) -> None:
        pg_conn.execute(f"CREATE ROLE {PRINCIPAL} LOGIN")
        env = _env_for(pg_settings, TEST_USER_PASSWORD="secret123")
        result = runner.invoke(
            app, ["plan", "--file", str(FIXTURES / "principal-analyst.yaml")], env=env
        )
        assert result.exit_code == 0

    def test_apply_principal_then_grant(
        self, pg_conn: psycopg.Connection, pg_settings: AppSettings
    ) -> None:
        """Full workflow: create principal, then grant permissions."""
        env = _env_for(pg_settings, TEST_USER_PASSWORD="secret123")

        result = runner.invoke(
            app, ["apply", "--file", str(FIXTURES / "principal-analyst.yaml")], env=env
        )
        assert result.exit_code == 0
        assert _principal_exists(pg_conn, PRINCIPAL)

        result = runner.invoke(
            app, ["apply", "--file", str(FIXTURES / "analyst-finance.yaml")], env=env
        )
        assert result.exit_code == 0
        assert _grant_count(pg_conn, PRINCIPAL) >= 2


# ── Multi-file support ───────────────────────────────────────────────────


class TestPostgresMultiFile:
    pytestmark = pytest.mark.usefixtures("pg_e2e")

    def test_apply_multiple_files(
        self, pg_conn: psycopg.Connection, pg_settings: AppSettings
    ) -> None:
        """Apply with space-separated principal + grant files."""
        env = _env_for(pg_settings, TEST_USER_PASSWORD="secret123")

        files = f"{FIXTURES / 'principal-analyst.yaml'} {FIXTURES / 'analyst-finance.yaml'}"
        result = runner.invoke(app, ["apply", "--file", files], env=env)
        assert result.exit_code == 0
        assert _principal_exists(pg_conn, PRINCIPAL)
        assert _grant_count(pg_conn, PRINCIPAL) >= 2

    def test_plan_multiple_files(
        self, pg_conn: psycopg.Connection, pg_settings: AppSettings
    ) -> None:
        """Plan with space-separated principal + grant files."""
        env = _env_for(pg_settings, TEST_USER_PASSWORD="secret123")

        files = f"{FIXTURES / 'principal-analyst.yaml'} {FIXTURES / 'analyst-finance.yaml'}"
        result = runner.invoke(app, ["plan", "--file", files], env=env)
        # Plan should not fail — principal doesn't exist yet but it's in the plan
        assert result.exit_code == 0
