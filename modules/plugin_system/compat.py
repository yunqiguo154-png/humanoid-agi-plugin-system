from __future__ import annotations

import warnings


class MigrationRequiredError(RuntimeError):
    """Raised when a legacy compatibility path is unsafe for production."""


def warn_legacy_api(name: str) -> None:
    warnings.warn(
        f"{name} is a deprecated legacy plugin compatibility API. "
        "Use plugin.yaml entrypoints, PluginEngine, PluginGateway, and signed registry workflows for production.",
        DeprecationWarning,
        stacklevel=3,
    )
