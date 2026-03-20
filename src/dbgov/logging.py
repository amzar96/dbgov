from __future__ import annotations

import sys

from loguru import logger

logger.remove()

logger.add(
    sys.stderr,
    level="DEBUG",
    serialize=True,
)

__all__ = ["logger"]
