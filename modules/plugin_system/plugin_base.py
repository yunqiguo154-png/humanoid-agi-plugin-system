from __future__ import annotations

import importlib
from typing import Any
from typing import Callable

from .compat import warn_legacy_api


class PluginBase:
    """Legacy class-based plugin compatibility base.

    The modern runtime uses plugin.yaml + function entrypoints. This class keeps
    old plugin code import-compatible and offers best-effort tool registry hooks.
    """

    plugin_name: str = "unknown_plugin"
    plugin_version: str = "0.0.1"
    plugin_description: str = ""
    plugin_author: str = ""
    required_permissions: list[str] = []
    max_memory_mb: int = 100
    max_cpu_percent: float = 10.0

    def __init__(self, plugin_api: Any | None = None, api: Any | None = None) -> None:
        warn_legacy_api("PluginBase")
        resolved_api = plugin_api if plugin_api is not None else api
        # Keep both names for compatibility with old/new plugin code.
        self.plugin_api = resolved_api
        self.api = resolved_api
        self.is_enabled = False
        self._registered_tools: dict[str, Callable[..., Any]] = {}

    def on_load(self) -> bool:
        return True

    def on_unload(self) -> bool:
        return True

    def on_user_input(self, user_input: str, context: list[dict[str, Any]]) -> dict[str, Any] | None:
        _ = user_input
        _ = context
        return None

    def on_output(self, output_content: str) -> str | None:
        _ = output_content
        return None

    def register_tool(
        self,
        name: str,
        func: Callable[..., Any],
        description: str = "",
        params: dict[str, str] | None = None,
    ) -> bool:
        if not isinstance(name, str) or not name.strip():
            return False
        if not callable(func):
            return False
        tool_name = name.strip()

        registry = self._load_tool_registry()
        if registry is not None:
            try:
                registry.register_tool(
                    name=tool_name,
                    func=func,
                    description=description or getattr(func, "__doc__", "") or "",
                    params=params or {},
                    source="plugin",
                    plugin_name=self.plugin_name,
                )
            except Exception:
                return False

        self._registered_tools[tool_name] = func
        return True

    def unregister_tools(self) -> int:
        count = len(self._registered_tools)
        registry = self._load_tool_registry()
        if registry is not None:
            try:
                registry_count = registry.unregister_by_plugin(self.plugin_name)
                if isinstance(registry_count, int):
                    count = registry_count
            except Exception:
                pass
        self._registered_tools.clear()
        return count

    def get_tools(self) -> dict[str, Callable[..., Any]]:
        return dict(self._registered_tools)

    def get_status(self) -> dict[str, Any]:
        return {
            "plugin_name": self.plugin_name,
            "plugin_version": self.plugin_version,
            "plugin_description": self.plugin_description,
            "is_enabled": self.is_enabled,
            "required_permissions": list(self.required_permissions),
            "registered_tools": sorted(self._registered_tools.keys()),
        }

    def _load_tool_registry(self) -> Any | None:
        try:
            module = importlib.import_module("infra.tool_manager.tool_registry")
        except Exception:
            return None
        return getattr(module, "ToolRegistry", None)
