from __future__ import annotations

from pathlib import Path
from typing import Any

from .compat import warn_legacy_api
from .market import PluginMarket
from .plugin_api import PluginAPI
from .plugin_manager import PluginManager
from .plugin_sandbox import PluginSandbox


class PluginSystemCore:
    """Legacy system-core compatibility facade."""

    def __init__(
        self,
        memory_module: Any | None = None,
        output_system: Any | None = None,
        adaptive_system: Any | None = None,
        *,
        plugins_dir: str | Path = "data/plugins",
        production_mode: bool = False,
        sandbox_backend: str = "auto",
        require_signatures: bool = False,
        require_enforced_sandbox: bool = False,
        market_url: str = "https://plugins.example.com/api",
    ) -> None:
        warn_legacy_api("PluginSystemCore")
        self.plugin_api = PluginAPI(memory_module, output_system, adaptive_system)
        self.api = self.plugin_api
        self.sandbox = PluginSandbox()
        self.manager = PluginManager(
            self.plugin_api,
            self.sandbox,
            plugins_dir=plugins_dir,
            production_mode=production_mode,
            sandbox_backend=sandbox_backend,
            require_signatures=require_signatures,
            require_enforced_sandbox=require_enforced_sandbox,
        )
        self.engine = self.manager.engine
        self.market = PluginMarket(market_url=market_url, production_mode=production_mode)
        self.is_enabled = True
        self.is_running = False

    async def start(self) -> None:
        self.manager.discover_plugins()
        self.is_running = True

    async def stop(self) -> None:
        for plugin in self.manager.get_all_plugins():
            self.manager.unload_plugin(plugin.plugin_name, user_auth=True)
        self.is_running = False

    def discover_plugins(self) -> list[str]:
        return self.manager.discover_plugins()

    def install_plugin(self, package_path: str | Path, **kwargs: Any) -> Any:
        return self.manager.install_plugin(package_path, **kwargs)

    def approve_permissions(self, name: str, permissions: list[dict[str, Any]] | None = None, **kwargs: Any) -> Any:
        return self.manager.approve_permissions(name, permissions, **kwargs)

    def enable_plugin(self, name: str, **kwargs: Any) -> Any:
        return self.manager.enable_plugin(name, **kwargs)

    def disable_plugin(self, name: str, **kwargs: Any) -> Any:
        return self.manager.disable_plugin(name, **kwargs)

    def start_plugin(self, name: str) -> Any:
        return self.manager.start_plugin(name)

    def stop_plugin(self, name: str) -> None:
        self.manager.stop_plugin(name)

    def load_plugin(self, plugin_name: str, user_auth: bool = False) -> bool:
        return self.manager.load_plugin(plugin_name, user_auth=user_auth)

    def unload_plugin(self, plugin_name: str, user_auth: bool = False) -> bool:
        return self.manager.unload_plugin(plugin_name, user_auth=user_auth)

    def reload_plugin(self, plugin_name: str, user_auth: bool = False) -> bool:
        return self.manager.reload_plugin(plugin_name, user_auth=user_auth)

    def process_user_input(self, user_input: str, context: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not self.is_enabled or not self.is_running:
            return []
        return self.manager.trigger_on_user_input(user_input, context)

    def process_output(self, output_content: str) -> str:
        if not self.is_enabled or not self.is_running:
            return output_content
        return self.manager.trigger_on_output(output_content)

    def set_enabled(self, enable: bool, user_auth: bool = False) -> None:
        if not user_auth:
            return
        self.is_enabled = enable

    def get_status(self) -> dict[str, Any]:
        return {
            "is_running": self.is_running,
            "is_enabled": self.is_enabled,
            "loaded_plugins": [item.get_status() for item in self.manager.get_all_plugins()],
            "discovered_plugins": self.manager.discover_plugins(),
        }

    def call_tool(self, plugin_name: str, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        return self.manager.call_tool(plugin_name, tool_name, args)

    def shutdown(self) -> None:
        self.manager.stop_all()
        self.is_running = False
