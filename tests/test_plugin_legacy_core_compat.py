from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from modules.plugin_system.core import PluginSystemCore


class _MemoryStub:
    def get_context(self) -> list[dict[str, str]]:
        return [{"role": "user", "content": "hi"}]

    def retrieve(self, query: str, top_k: int) -> list[str]:
        return [f"{query}:{top_k}"]


class _OutputStub:
    def process(self, **kwargs: object) -> None:
        _ = kwargs


class _AdaptiveStub:
    def get_current_status(self) -> dict[str, object]:
        return {"current_strategy": {"name": "legacy"}}


class LegacyCoreCompatTests(unittest.TestCase):
    def test_legacy_core_constructor_and_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            core = PluginSystemCore(
                _MemoryStub(),
                _OutputStub(),
                _AdaptiveStub(),
                plugins_dir=Path(temp_dir) / "plugins",
            )
            self.assertIs(core.api, core.plugin_api)
            self.assertTrue(core.is_enabled)
            self.assertFalse(core.is_running)
            self.assertEqual(core.process_user_input("hello", []), [])
            self.assertEqual(core.process_output("raw"), "raw")

            asyncio.run(core.start())
            self.assertTrue(core.is_running)
            status = core.get_status()
            self.assertIn("is_running", status)
            self.assertIn("is_enabled", status)
            self.assertIn("loaded_plugins", status)
            self.assertIn("discovered_plugins", status)

            core.set_enabled(False, user_auth=False)
            self.assertTrue(core.is_enabled)
            core.set_enabled(False, user_auth=True)
            self.assertFalse(core.is_enabled)
            self.assertEqual(core.process_output("raw"), "raw")

            core.set_enabled(True, user_auth=True)
            self.assertTrue(core.is_enabled)
            self.assertEqual(core.process_output("raw"), "raw")

            asyncio.run(core.stop())
            self.assertFalse(core.is_running)
            core.shutdown()

    def test_legacy_core_load_unload_auth_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            core = PluginSystemCore(plugins_dir=Path(temp_dir) / "plugins")
            asyncio.run(core.start())
            self.assertFalse(core.load_plugin("missing_plugin", user_auth=False))
            self.assertFalse(core.load_plugin("missing_plugin", user_auth=True))
            self.assertFalse(core.unload_plugin("missing_plugin", user_auth=False))
            self.assertFalse(core.unload_plugin("missing_plugin", user_auth=True))
            self.assertFalse(core.reload_plugin("missing_plugin", user_auth=False))
            self.assertFalse(core.reload_plugin("missing_plugin", user_auth=True))
            asyncio.run(core.stop())


if __name__ == "__main__":
    unittest.main()
