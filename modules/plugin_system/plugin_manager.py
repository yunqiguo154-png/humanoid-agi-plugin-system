from __future__ import annotations

import importlib.util
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .compat import MigrationRequiredError
from .compat import warn_legacy_api
from .engine import PluginEngine
from .models import InstalledPlugin, PluginMetadata
from .plugin_base import PluginBase
from .plugin_sandbox import PluginSandbox

_LEGACY_HIGH_RISK_PERMISSIONS = {"file_write", "network"}


@dataclass(frozen=True)
class LegacyPluginRuntime:
    plugin_name: str
    version: str = "0.0.0"
    status: str = "discovered"
    loaded: bool = False

    def get_status(self) -> dict[str, Any]:
        return {
            "plugin_name": self.plugin_name,
            "version": self.version,
            "status": self.status,
            "loaded": self.loaded,
        }


class PluginManager:
    """Legacy manager compatibility facade over PluginEngine."""

    def __init__(
        self,
        plugin_api: Any | None = None,
        sandbox: PluginSandbox | None = None,
        *,
        plugins_dir: str | Path = "data/plugins",
        engine: PluginEngine | None = None,
        production_mode: bool = False,
        sandbox_backend: str = "auto",
        require_signatures: bool = False,
        require_enforced_sandbox: bool = False,
        plugin_dir: str | Path = "plugins",
        allow_legacy_local_load: bool | None = None,
    ) -> None:
        warn_legacy_api("PluginManager")
        self.plugin_api = plugin_api
        self.sandbox = sandbox or PluginSandbox()
        if engine is None:
            sandbox_engine = getattr(self.sandbox, "engine", None)
            if isinstance(sandbox_engine, PluginEngine):
                engine = sandbox_engine
        self.engine = engine or PluginEngine(
            plugins_dir=plugins_dir,
            production_mode=production_mode,
            sandbox_backend=sandbox_backend,
            require_signatures=require_signatures,
            require_enforced_sandbox=require_enforced_sandbox,
        )
        self.production_mode = bool(production_mode or getattr(self.engine, "production_mode", False))
        self._plugin_dir = Path(plugin_dir).resolve()
        self._plugins: dict[str, PluginBase] = {}
        self._allow_legacy_local_load = (
            bool(allow_legacy_local_load) if allow_legacy_local_load is not None else (not self.production_mode)
        )
        if hasattr(self.sandbox, "bind_engine"):
            self.sandbox.bind_engine(self.engine)

    def discover_plugins(self) -> list[str]:
        discovered = set(self.engine.discover().keys())
        discovered.update(self._discover_legacy_plugins())
        return sorted(discovered)

    def list_plugins(self) -> list[str]:
        return self.discover_plugins()

    def get_all_plugins(self) -> list[Any]:
        loaded: list[Any] = [self._plugins[name] for name in sorted(self._plugins.keys())]
        discovered_engine = self.engine.discover()
        active = set(getattr(self.engine, "sandboxes", {}).keys())
        for name in sorted(discovered_engine):
            if name in self._plugins:
                continue
            metadata = discovered_engine[name]
            installed = self.engine.loader.get_installed(name)
            status = installed.status.value if installed is not None else "discovered"
            loaded.append(
                LegacyPluginRuntime(
                    plugin_name=name,
                    version=getattr(metadata, "version", "0.0.0"),
                    status=status,
                    loaded=name in active,
                )
            )
        return loaded

    def install_plugin(
        self,
        package_path: str | Path,
        *,
        replace: bool = True,
        signature: dict[str, Any] | None = None,
        install_dependencies: bool = False,
        scan_report: dict[str, Any] | None = None,
    ) -> PluginMetadata:
        return self.engine.install(
            package_path,
            replace=replace,
            signature=signature,
            install_dependencies=install_dependencies,
            scan_report=scan_report,
        )

    def approve_permissions(
        self,
        name: str,
        permissions: list[dict[str, Any]] | None = None,
        *,
        reviewer: str | None = "admin",
        review_reason: str | None = "legacy_approval",
    ) -> InstalledPlugin:
        return self.engine.grant_permissions(
            name,
            permissions,
            reviewer=reviewer,
            review_reason=review_reason,
        )

    def enable_plugin(self, name: str, *, actor: str | None = "admin", reason: str | None = "legacy_enable") -> InstalledPlugin:
        return self.engine.enable_plugin(name, actor=actor, reason=reason)

    def disable_plugin(
        self,
        name: str,
        *,
        actor: str | None = "admin",
        reason: str | None = "legacy_disable",
    ) -> InstalledPlugin:
        return self.engine.disable_plugin(name, actor=actor, reason=reason)

    def quarantine_plugin(
        self,
        name: str,
        *,
        actor: str | None = "admin",
        reason: str | None = "legacy_quarantine",
    ) -> InstalledPlugin:
        return self.engine.quarantine_plugin(name, actor=actor, reason=reason)

    def revoke_plugin(self, name: str, *, actor: str | None = "admin", reason: str | None = "legacy_revoke") -> InstalledPlugin:
        return self.engine.revoke_plugin(name, actor=actor, reason=reason)

    def start_plugin(self, name: str) -> Any:
        return self.engine.start_plugin(name)

    def stop_plugin(self, name: str) -> None:
        self.engine.stop_plugin(name)

    def stop_all(self) -> None:
        self.engine.stop_all()
        for name, plugin in list(self._plugins.items()):
            self.sandbox.wrap_call(plugin, plugin.on_unload)
            plugin.is_enabled = False
            self.sandbox.reset_plugin_resources(name)
            self._plugins.pop(name, None)

    def call_tool(self, plugin_name: str, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        return self.engine.call_tool(plugin_name, tool_name, args)

    # -------------------------------------------------------------------------
    # Legacy API surface
    # -------------------------------------------------------------------------
    def get_plugin(self, plugin_name: str) -> PluginBase | None:
        return self._plugins.get(plugin_name)

    def _load_metadata(self, plugin_name: str) -> dict[str, Any] | None:
        metadata_path = self._plugin_dir / plugin_name / "metadata.json"
        try:
            data = json.loads(metadata_path.read_text(encoding="utf-8"))
        except Exception:
            return None
        if isinstance(data, dict):
            return data
        return None

    def load_plugin(self, plugin_name: str, user_auth: bool = False) -> bool:
        if plugin_name in self._plugins:
            return False

        if plugin_name in self.engine.discover():
            try:
                self.engine.start_plugin(plugin_name)
            except Exception:
                pass
            else:
                return True

        if not self._allow_legacy_local_load or self.production_mode:
            if self.production_mode:
                raise MigrationRequiredError(
                    "legacy local plugin loading is disabled in production mode; "
                    "package the plugin with plugin.yaml, Ed25519 signing, SBOM, lockfile, scan report, and registry policy"
                )
            return False

        plugin_path = self._plugin_dir / plugin_name
        plugin_file = plugin_path / "plugin.py"
        if not plugin_file.exists() or not plugin_file.is_file():
            return False

        metadata = self._load_metadata(plugin_name)
        if not metadata:
            return False
        if not metadata.get("authorization", False):
            return False

        required_perms = metadata.get("required_permissions", [])
        if isinstance(required_perms, list):
            requires_user = any(str(permission) in _LEGACY_HIGH_RISK_PERMISSIONS for permission in required_perms)
            if requires_user and not user_auth:
                return False

        try:
            spec = importlib.util.spec_from_file_location(
                f"plugins.{plugin_name}.plugin",
                plugin_file,
            )
            if spec is None or spec.loader is None:
                return False
            plugin_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plugin_module)
            plugin_class = self._find_plugin_class(plugin_module)
            if plugin_class is None:
                return False
            plugin_instance = plugin_class(self.plugin_api)
            plugin_instance.plugin_name = str(metadata.get("name", plugin_name))
            plugin_instance.plugin_version = str(metadata.get("version", getattr(plugin_instance, "plugin_version", "0.0.1")))
            if isinstance(required_perms, list):
                plugin_instance.required_permissions = [str(item) for item in required_perms]
            max_memory_mb = metadata.get("max_memory_mb")
            if isinstance(max_memory_mb, int):
                plugin_instance.max_memory_mb = max_memory_mb
            result = self.sandbox.wrap_call(plugin_instance, plugin_instance.on_load)
            if result is None:
                return False
            plugin_instance.is_enabled = True
            self._plugins[plugin_name] = plugin_instance
            return True
        except Exception:
            return False

    def unload_plugin(self, plugin_name: str, user_auth: bool = False) -> bool:
        plugin = self._plugins.get(plugin_name)
        if plugin is not None:
            required_perms = plugin.required_permissions if isinstance(plugin.required_permissions, list) else []
            if any(str(permission) in _LEGACY_HIGH_RISK_PERMISSIONS for permission in required_perms) and not user_auth:
                return False
            result = self.sandbox.wrap_call(plugin, plugin.on_unload)
            if not result:
                return False
            plugin.is_enabled = False
            self._plugins.pop(plugin_name, None)
            self.sandbox.reset_plugin_resources(plugin_name)
            return True

        if plugin_name not in self.engine.discover() and plugin_name not in getattr(self.engine, "sandboxes", {}):
            return False
        try:
            self.engine.stop_plugin(plugin_name)
        except Exception:
            return False
        return True

    def reload_plugin(self, plugin_name: str, user_auth: bool = False) -> bool:
        if not user_auth:
            return False
        self.unload_plugin(plugin_name, user_auth=user_auth)
        return self.load_plugin(plugin_name, user_auth=user_auth)

    def trigger_on_user_input(self, user_input: str, context: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for plugin in list(self._plugins.values()):
            if not plugin.is_enabled:
                continue
            result = self.sandbox.wrap_call(plugin, plugin.on_user_input, user_input, context)
            if isinstance(result, dict):
                results.append(result)
        sandboxes = getattr(self.engine, "sandboxes", {})
        if not sandboxes:
            return results
        tool_map = self.engine.tools()
        for plugin_name in sorted(sandboxes.keys()):
            if plugin_name in self._plugins:
                continue
            plugin_tools = tool_map.get(plugin_name, {})
            if "on_user_input" not in plugin_tools:
                continue
            try:
                response = self.engine.call_tool(
                    plugin_name,
                    "on_user_input",
                    {"user_input": user_input, "context": context},
                )
            except Exception:
                continue
            payload = response.get("data") if isinstance(response, dict) else None
            if isinstance(payload, dict):
                results.append(payload)
        return results

    def trigger_on_output(self, output_content: str) -> str:
        final_content = output_content
        for plugin in list(self._plugins.values()):
            if not plugin.is_enabled:
                continue
            modified = self.sandbox.wrap_call(plugin, plugin.on_output, final_content)
            if isinstance(modified, str) and modified:
                final_content = modified

        sandboxes = getattr(self.engine, "sandboxes", {})
        if not sandboxes:
            return final_content
        tool_map = self.engine.tools()
        for plugin_name in sorted(sandboxes.keys()):
            if plugin_name in self._plugins:
                continue
            plugin_tools = tool_map.get(plugin_name, {})
            if "on_output" not in plugin_tools:
                continue
            try:
                response = self.engine.call_tool(
                    plugin_name,
                    "on_output",
                    {"output_content": final_content},
                )
            except Exception:
                continue
            payload = response.get("data") if isinstance(response, dict) else None
            if isinstance(payload, str) and payload:
                final_content = payload
            elif isinstance(payload, dict):
                candidate = payload.get("output") or payload.get("content") or payload.get("text")
                if isinstance(candidate, str) and candidate:
                    final_content = candidate
        return final_content

    def _discover_legacy_plugins(self) -> list[str]:
        if not self._plugin_dir.exists() or not self._plugin_dir.is_dir():
            return []
        discovered: list[str] = []
        for item in sorted(os.listdir(self._plugin_dir)):
            plugin_path = self._plugin_dir / item
            metadata_path = plugin_path / "metadata.json"
            plugin_file = plugin_path / "plugin.py"
            if plugin_path.is_dir() and metadata_path.exists() and plugin_file.exists():
                discovered.append(item)
        return discovered

    def _find_plugin_class(self, module: Any) -> type[PluginBase] | None:
        for attr_name in dir(module):
            candidate = getattr(module, attr_name)
            if isinstance(candidate, type) and issubclass(candidate, PluginBase) and candidate is not PluginBase:
                return candidate
        return None
