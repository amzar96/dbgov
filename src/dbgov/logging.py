from __future__ import annotations

import os
import sys

from loguru import logger

logger.remove()

_fmt = (
    "<level>{level: <8}</level> | "
    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
    "<level>{message}</level> "
    "{extra}"
)

logger.add(
    sys.stderr,
    level=os.environ.get("DBGOV_LOG_LEVEL", "INFO"),
    format=_fmt,
    serialize=os.environ.get("DBGOV_LOG_FORMAT") == "json",
    colorize=sys.stderr.isatty(),
)

__all__ = ["logger"]
