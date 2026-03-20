from __future__ import annotations

from typing import TYPE_CHECKING

from dbgov.adapters.mysql import MySQLAdapter
from dbgov.adapters.postgres import PostgresAdapter
from dbgov.adapters.redshift import RedshiftAdapter

if TYPE_CHECKING:
    from dbgov.adapters.base import BaseAdapter
    from dbgov.settings.config import AppSettings

_ENGINE_MAP: dict[str, type[BaseAdapter]] = {
    "postgres": PostgresAdapter,
    "postgresql": PostgresAdapter,
    "redshift": RedshiftAdapter,
    "mysql": MySQLAdapter,
    "mariadb": MySQLAdapter,
}


def get_adapter(settings: AppSettings) -> BaseAdapter:
    engine_lower = settings.engine.lower().strip()
    adapter_cls = _ENGINE_MAP.get(engine_lower)
    if adapter_cls is None:
        supported = ", ".join(sorted(_ENGINE_MAP.keys()))
        raise ValueError(f"Unsupported engine '{settings.engine}'. Supported: {supported}")
    return adapter_cls(settings)
