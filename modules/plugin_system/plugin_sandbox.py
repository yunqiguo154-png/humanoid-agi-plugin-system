from __future__ import annotations

import os
from typing import Any

from .compat import warn_legacy_api
from .engine import PluginEngine
from .sandbox import SandboxManager, SandboxViolation


class PluginSandbox:
    """Legacy sandbox compatibility wrapper.

    This wrapper controls a single plugin runtime through PluginEngine.
    """

    def __init__(self, engine: PluginEngine | None = None, plugin_name: str | None = None) -> None:
        warn_legacy_api("PluginSandbox")
        self.engine = engine
        self.plugin_name = plugin_name
        self._plugin_resources: dict[str, dict[str, int]] = {}

    def bind_engine(self, engine: PluginEngine) -> None:
        self.engine = engine

    def start(self, plugin_name: str | None = None) -> SandboxManager:
        if self.engine is None:
            raise RuntimeError("plugin sandbox is not bound to an engine")
        name = plugin_name or self.plugin_name
        if not name:
            raise ValueError("plugin name is required")
        self.plugin_name = name
        return self.engine.start_plugin(name)

    def stop(self, plugin_name: str | None = None) -> None:
        if self.engine is None:
            return
        name = plugin_name or self.plugin_name
        if not name:
            return
        self.engine.stop_plugin(name)

    def call_tool(
        self,
        tool_name: str,
        args: dict[str, Any],
        *,
        plugin_name: str | None = None,
    ) -> dict[str, Any]:
        if self.engine is None:
            raise RuntimeError("plugin sandbox is not bound to an engine")
        name = plugin_name or self.plugin_name
        if not name:
            raise ValueError("plugin name is required")
        return self.engine.call_tool(name, tool_name, args)

    @property
    def runtime(self) -> SandboxManager | None:
        if self.engine is None or not self.plugin_name:
            return None
        return self.engine.sandboxes.get(self.plugin_name)

    # ------------------------------------------------------------------
    # Legacy helpers used by old PluginManager implementations.
    # ------------------------------------------------------------------
    def check_resources(self, plugin: Any) -> bool:
        plugin_name = str(getattr(plugin, "plugin_name", "unknown_plugin"))
        current_memory_mb = self._current_memory_mb()
        resources = self._plugin_resources.setdefault(
            plugin_name,
            {"base_memory": current_memory_mb, "peak_memory": current_memory_mb},
        )
        base_memory = int(resources.get("base_memory", current_memory_mb))
        used_memory = max(0, current_memory_mb - base_memory)
        max_memory_mb = int(getattr(plugin, "max_memory_mb", 100))
        if used_memory > max_memory_mb:
            return False
        if current_memory_mb > int(resources.get("peak_memory", current_memory_mb)):
            resources["peak_memory"] = current_memory_mb
        resources["used_memory"] = used_memory
        return True

    def wrap_call(self, plugin: Any, func: Any, *args: Any, **kwargs: Any) -> Any:
        if not self.check_resources(plugin):
            return None
        if not callable(func):
            return None
        try:
            return func(*args, **kwargs)
        except Exception:
            return None

    def reset_plugin_resources(self, plugin_name: str) -> None:
        self._plugin_resources.pop(plugin_name, None)

    def get_plugin_resource_usage(self, plugin_name: str) -> dict[str, int]:
        return dict(self._plugin_resources.get(plugin_name, {}))

    def _current_memory_mb(self) -> int:
        try:
            import psutil

            return int(psutil.Process().memory_info().rss // (1024**2))
        except Exception:
            try:
                import resource

                usage = resource.getrusage(resource.RUSAGE_SELF)
                value = int(usage.ru_maxrss)
                # Linux reports KiB, macOS reports bytes. Windows normally uses
                # the psutil branch; this fallback is best-effort only.
                if os.name == "posix" and value > 1024 * 1024:
                    return value // (1024 * 1024)
                return value // 1024
            except Exception:
                return 0


__all__ = ["PluginSandbox", "SandboxViolation", "SandboxManager"]
