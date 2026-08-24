# src/app/infrastructure/database/__init__.py

"""
This file marks the 'database' directory as a Python package and exposes
key components for easy importing.
"""

from importlib import import_module
from typing import Any

from .base import Base

__all__ = ["Base", "get_db", "AsyncSessionLocal"]


def __getattr__(name: str) -> Any:
    """Load runtime database objects only when an application requests them."""
    if name in {"AsyncSessionLocal", "get_db"}:
        database = import_module(".database", __name__)
        return getattr(database, name)
    raise AttributeError(name)
