from __future__ import annotations

from unittest.mock import patch
import unittest

import modules.plugin_system as plugin_system
from modules.plugin_system.core import PluginSystemCore
from modules.plugin_system.plugin_base import PluginBase
from modules.plugin_system.plugin_manager import PluginManager
from modules.plugin_system.plugin_sandbox import PluginSandbox


class _EngineStub:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []

    def discover(self) -> dict[str, object]:
        self.calls.append(("discover", tuple(), {}))
        return {"hello": object()}

    def install(self, package_path: str, **kwargs: object) -> dict[str, object]:
        self.calls.append(("install", (package_path,), kwargs))
        return {"name": "hello"}

    def grant_permissions(self, name: str, permissions: object, **kwargs: object) -> dict[str, object]:
        self.calls.append(("grant_permissions", (name, permissions), kwargs))
        return {"name": name}

    def enable_plugin(self, name: str, **kwargs: object) -> dict[str, object]:
        self.calls.append(("enable_plugin", (name,), kwargs))
        return {"name": name}

    def disable_plugin(self, name: str, **kwargs: object) -> dict[str, object]:
        self.calls.append(("disable_plugin", (name,), kwargs))
        return {"name": name}

    def quarantine_plugin(self, name: str, **kwargs: object) -> dict[str, object]:
        self.calls.append(("quarantine_plugin", (name,), kwargs))
        return {"name": name}

    def revoke_plugin(self, name: str, **kwargs: object) -> dict[str, object]:
        self.calls.append(("revoke_plugin", (name,), kwargs))
        return {"name": name}

    def start_plugin(self, name: str) -> dict[str, object]:
        self.calls.append(("start_plugin", (name,), {}))
        return {"name": name}

    def stop_plugin(self, name: str) -> None:
        self.calls.append(("stop_plugin", (name,), {}))

    def stop_all(self) -> None:
        self.calls.append(("stop_all", tuple(), {}))

    def call_tool(self, plugin_name: str, tool_name: str, args: dict[str, object]) -> dict[str, object]:
        self.calls.append(("call_tool", (plugin_name, tool_name, args), {}))
        return {"status": "success"}

    sandboxes: dict[str, object] = {}


class LegacyInitExportTests(unittest.TestCase):
    def test_legacy_exports_available(self) -> None:
        self.assertTrue(hasattr(plugin_system, "PluginSystemCore"))
        self.assertTrue(hasattr(plugin_system, "PluginBase"))
        self.assertTrue(hasattr(plugin_system, "PluginManager"))
        self.assertTrue(hasattr(plugin_system, "PluginSandbox"))
        self.assertTrue(hasattr(plugin_system, "store_router"))

    def test_plugin_base_default_hooks(self) -> None:
        plugin = PluginBase(api={"k": "v"})
        self.assertEqual(plugin.api, {"k": "v"})
        self.assertEqual(plugin.plugin_api, {"k": "v"})
        self.assertTrue(plugin.on_load())
        self.assertTrue(plugin.on_unload())
        self.assertIsNone(plugin.on_user_input("hello", []))
        self.assertIsNone(plugin.on_output("output"))
        status = plugin.get_status()
        self.assertIn("plugin_name", status)
        self.assertIn("registered_tools", status)

    def test_plugin_base_tool_registration_local_fallback(self) -> None:
        plugin = PluginBase(api=None)

        def sample_tool() -> int:
            return 1

        self.assertTrue(plugin.register_tool("sample", sample_tool, "sample desc"))
        tools = plugin.get_tools()
        self.assertIn("sample", tools)
        self.assertEqual(tools["sample"](), 1)
        self.assertEqual(plugin.unregister_tools(), 1)
        self.assertEqual(plugin.get_tools(), {})

    def test_plugin_base_tool_registration_with_external_registry(self) -> None:
        plugin = PluginBase(api=None)

        class _RegistryStub:
            calls: list[tuple[str, dict[str, object]]] = []

            @classmethod
            def register_tool(cls, **kwargs: object) -> None:
                cls.calls.append(("register", dict(kwargs)))

            @classmethod
            def unregister_by_plugin(cls, plugin_name: str) -> int:
                cls.calls.append(("unregister", {"plugin_name": plugin_name}))
                return 3

        class _ModuleStub:
            ToolRegistry = _RegistryStub

        with patch("importlib.import_module", return_value=_ModuleStub):
            self.assertTrue(plugin.register_tool("sample", lambda: 2))
            self.assertEqual(plugin.unregister_tools(), 3)

        self.assertEqual(_RegistryStub.calls[0][0], "register")
        self.assertEqual(_RegistryStub.calls[1][0], "unregister")

    def test_plugin_manager_delegates_to_engine(self) -> None:
        engine = _EngineStub()
        manager = PluginManager(engine=engine)  # type: ignore[arg-type]
        self.assertEqual(sorted(manager.list_plugins()), ["hello"])
        self.assertEqual(manager.install_plugin("pkg.zip"), {"name": "hello"})
        self.assertEqual(
            manager.approve_permissions("hello", [{"name": "compute", "value": True}], reviewer="ops"),
            {"name": "hello"},
        )
        self.assertEqual(manager.enable_plugin("hello"), {"name": "hello"})
        self.assertEqual(manager.call_tool("hello", "run", {}), {"status": "success"})
        manager.stop_all()
        method_names = [item[0] for item in engine.calls]
        self.assertIn("discover", method_names)
        self.assertIn("install", method_names)
        self.assertIn("grant_permissions", method_names)
        self.assertIn("enable_plugin", method_names)
        self.assertIn("call_tool", method_names)
        self.assertIn("stop_all", method_names)

    def test_plugin_sandbox_wrapper_delegates(self) -> None:
        engine = _EngineStub()
        sandbox = PluginSandbox(engine, "hello")  # type: ignore[arg-type]
        self.assertEqual(sandbox.start(), {"name": "hello"})
        self.assertEqual(sandbox.call_tool("run", {"q": 1}), {"status": "success"})
        sandbox.stop()
        method_names = [item[0] for item in engine.calls]
        self.assertEqual(method_names, ["start_plugin", "call_tool", "stop_plugin"])

    def test_plugin_sandbox_legacy_resource_helpers(self) -> None:
        plugin = PluginBase(api=None)
        plugin.plugin_name = "resource_plugin"
        plugin.max_memory_mb = 100
        sandbox = PluginSandbox()

        self.assertTrue(sandbox.check_resources(plugin))
        usage = sandbox.get_plugin_resource_usage("resource_plugin")
        self.assertIn("base_memory", usage)
        self.assertIn("peak_memory", usage)
        self.assertEqual(sandbox.wrap_call(plugin, lambda value: value + 1, 1), 2)
        self.assertIsNone(sandbox.wrap_call(plugin, lambda: (_ for _ in ()).throw(RuntimeError("boom"))))
        sandbox.reset_plugin_resources("resource_plugin")
        self.assertEqual(sandbox.get_plugin_resource_usage("resource_plugin"), {})

    def test_plugin_system_core_bootstraps(self) -> None:
        core = PluginSystemCore()
        self.assertIsNotNone(core.manager)
        self.assertIsNotNone(core.engine)
        self.assertIsNotNone(core.api)
        self.assertIsNotNone(core.market)
        core.shutdown()


if __name__ == "__main__":
    unittest.main()
