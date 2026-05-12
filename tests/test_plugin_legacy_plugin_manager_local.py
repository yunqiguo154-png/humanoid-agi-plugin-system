from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from modules.plugin_system.compat import MigrationRequiredError
from modules.plugin_system.plugin_api import PluginAPI
from modules.plugin_system.plugin_manager import PluginManager
from modules.plugin_system.plugin_sandbox import PluginSandbox


class _EngineStub:
    production_mode = False
    sandboxes: dict[str, object] = {}

    class _LoaderStub:
        @staticmethod
        def get_installed(name: str) -> None:
            _ = name
            return None

    loader = _LoaderStub()

    def discover(self) -> dict[str, object]:
        return {}

    def stop_all(self) -> None:
        return None

    def start_plugin(self, name: str) -> object:
        raise RuntimeError(f"not installed: {name}")

    def stop_plugin(self, name: str) -> None:
        _ = name
        return None

    def tools(self) -> dict[str, dict[str, str]]:
        return {}

    def call_tool(self, plugin_name: str, tool_name: str, args: dict[str, object]) -> dict[str, object]:
        _ = plugin_name
        _ = tool_name
        _ = args
        return {"status": "success"}


class LegacyPluginManagerLocalTests(unittest.TestCase):
    def _write_legacy_plugin(self, root: Path, *, required_permissions: list[str]) -> None:
        plugin_dir = root / "demo"
        plugin_dir.mkdir(parents=True)
        (plugin_dir / "metadata.json").write_text(
            json.dumps(
                {
                    "name": "demo_plugin",
                    "version": "1.0.0",
                    "authorization": True,
                    "required_permissions": required_permissions,
                    "max_memory_mb": 128,
                }
            ),
            encoding="utf-8",
        )
        (plugin_dir / "plugin.py").write_text(
            "\n".join(
                [
                    "from modules.plugin_system.plugin_base import PluginBase",
                    "",
                    "class DemoPlugin(PluginBase):",
                    "    plugin_name = 'demo_plugin'",
                    "    def on_load(self):",
                    "        return True",
                    "    def on_unload(self):",
                    "        return True",
                    "    def on_user_input(self, user_input, context):",
                    "        return {'plugin': self.plugin_name, 'input': user_input}",
                    "    def on_output(self, output_content):",
                    "        return output_content + '|demo'",
                ]
            ),
            encoding="utf-8",
        )

    def test_local_legacy_plugin_load_unload_and_triggers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._write_legacy_plugin(root, required_permissions=["network"])
            manager = PluginManager(
                plugin_api=PluginAPI(),
                sandbox=PluginSandbox(),
                engine=_EngineStub(),  # type: ignore[arg-type]
                plugin_dir=root,
                production_mode=False,
                allow_legacy_local_load=True,
            )
            self.assertIn("demo", manager.discover_plugins())
            self.assertFalse(manager.load_plugin("demo", user_auth=False))
            self.assertTrue(manager.load_plugin("demo", user_auth=True))
            plugin = manager.get_plugin("demo")
            self.assertIsNotNone(plugin)
            assert plugin is not None
            self.assertTrue(plugin.is_enabled)
            user_results = manager.trigger_on_user_input("hello", [])
            self.assertEqual(user_results[0]["plugin"], "demo_plugin")
            self.assertEqual(manager.trigger_on_output("x"), "x|demo")
            self.assertTrue(manager.reload_plugin("demo", user_auth=True))
            self.assertTrue(manager.unload_plugin("demo", user_auth=True))
            self.assertIsNone(manager.get_plugin("demo"))

    def test_production_mode_rejects_legacy_local_plugin_loading(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._write_legacy_plugin(root, required_permissions=[])
            manager = PluginManager(
                plugin_api=PluginAPI(),
                sandbox=PluginSandbox(),
                engine=_EngineStub(),  # type: ignore[arg-type]
                plugin_dir=root,
                production_mode=True,
                allow_legacy_local_load=True,
            )
            with self.assertRaises(MigrationRequiredError):
                manager.load_plugin("demo", user_auth=True)


if __name__ == "__main__":
    unittest.main()
