"""Importing this package registers every check module's checks as a side effect."""

import importlib
import pkgutil

for _mod in pkgutil.iter_modules(__path__):
    importlib.import_module(f"{__name__}.{_mod.name}")

from cspm_scan.core.registry import CHECK_REGISTRY  # noqa: E402
