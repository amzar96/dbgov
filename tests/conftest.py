from __future__ import annotations

import contextlib
import os
import time
from typing import TYPE_CHECKING

import psycopg
import pymysql  # type: ignore[import-untyped]
import pytest

from dbgov.settings.config import AppSettings

if TYPE_CHECKING:
    from collections.abc import Generator


def _wait_for_postgres(settings: AppSettings, retries: int = 30) -> None:
    for _ in range(retries):
        try:
            conn = psycopg.connect(
                host=settings.host,
                port=settings.port,
                dbname=settings.name,
                user=settings.user,
                password=settings.password,
            )
            conn.close()
            return
        except Exception:
            time.sleep(1)
    raise TimeoutError("Postgres not ready")


def _wait_for_mysql(settings: AppSettings, retries: int = 60) -> None:
    for _ in range(retries):
        try:
            conn = pymysql.connect(
                host=settings.host,
                port=settings.port,
                database=settings.name,
                user=settings.user,
                password=settings.password,
            )
            conn.close()
            return
        except Exception:
            time.sleep(1)
    raise TimeoutError("MySQL not ready")


@pytest.fixture(scope="session")
def pg_settings() -> AppSettings:
    return AppSettings(
        engine="postgres",
        host=os.environ.get("DBGOV_TEST_PG_HOST", "127.0.0.1"),
        port=int(os.environ.get("DBGOV_TEST_PG_PORT", "15432")),
        name="dbgov_test",
        user="dbgov",
        password="dbgov",
    )


@pytest.fixture(scope="session")
def mysql_settings() -> AppSettings:
    return AppSettings(
        engine="mysql",
        host=os.environ.get("DBGOV_TEST_MYSQL_HOST", "127.0.0.1"),
        port=int(os.environ.get("DBGOV_TEST_MYSQL_PORT", "13306")),
        name="dbgov_test",
        user="root",
        password="root",
    )


@pytest.fixture(scope="session")
def _pg_ready(pg_settings: AppSettings) -> None:
    _wait_for_postgres(pg_settings)


@pytest.fixture(scope="session")
def _mysql_ready(mysql_settings: AppSettings) -> None:
    _wait_for_mysql(mysql_settings)


@pytest.fixture(scope="session")
def pg_conn(_pg_ready: None, pg_settings: AppSettings) -> Generator[psycopg.Connection, None, None]:
    conn = psycopg.connect(
        host=pg_settings.host,
        port=pg_settings.port,
        dbname=pg_settings.name,
        user=pg_settings.user,
        password=pg_settings.password,
        autocommit=True,
    )
    yield conn
    conn.close()


def _pg_cleanup(conn: psycopg.Connection) -> None:
    conn.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM test_user")
    conn.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM test_user")
    conn.execute("REVOKE USAGE ON SCHEMA public FROM test_user")
    conn.execute("DROP TABLE IF EXISTS public.orders")
    conn.execute("DROP TABLE IF EXISTS public.customers")
    conn.execute("REASSIGN OWNED BY test_user TO dbgov")
    conn.execute("DROP OWNED BY test_user")
    conn.execute("DROP ROLE IF EXISTS test_user")


@pytest.fixture()
def pg_setup(pg_conn: psycopg.Connection) -> Generator[None, None, None]:
    with contextlib.suppress(Exception):
        _pg_cleanup(pg_conn)
    pg_conn.execute("CREATE ROLE test_user LOGIN")
    pg_conn.execute("CREATE TABLE IF NOT EXISTS public.orders (id int)")
    pg_conn.execute("CREATE TABLE IF NOT EXISTS public.customers (id int)")

    yield

    _pg_cleanup(pg_conn)


@pytest.fixture()
def mysql_conn(
    _mysql_ready: None, mysql_settings: AppSettings
) -> Generator[pymysql.Connection, None, None]:
    conn = pymysql.connect(
        host=mysql_settings.host,
        port=mysql_settings.port,
        database=mysql_settings.name,
        user=mysql_settings.user,
        password=mysql_settings.password,
        autocommit=True,
    )
    with conn.cursor() as cur:
        cur.execute("DROP USER IF EXISTS 'test_user'@'%'")
        cur.execute("CREATE USER 'test_user'@'%' IDENTIFIED BY 'testpass'")
        cur.execute("CREATE TABLE IF NOT EXISTS orders (id INT)")
        cur.execute("CREATE TABLE IF NOT EXISTS customers (id INT)")

    yield conn

    with conn.cursor() as cur:
        with contextlib.suppress(Exception):
            cur.execute("REVOKE ALL PRIVILEGES ON dbgov_test.* FROM 'test_user'@'%'")
        cur.execute("DROP USER IF EXISTS 'test_user'@'%'")
        cur.execute("DROP TABLE IF EXISTS orders")
        cur.execute("DROP TABLE IF EXISTS customers")
    conn.close()
