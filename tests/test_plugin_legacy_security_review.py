from __future__ import annotations

import asyncio
import tempfile
import unittest
import warnings
from pathlib import Path

from modules.plugin_system.compat import MigrationRequiredError
from modules.plugin_system.core import PluginSystemCore
from modules.plugin_system.market import PluginMarket
from modules.plugin_system.plugin_api import PluginAPI
from modules.plugin_system.plugin_base import PluginBase
from modules.plugin_system.plugin_manager import PluginManager
from modules.plugin_system.plugin_sandbox import PluginSandbox
from modules.plugin_system.store_api import get_categories
from tests.test_plugin_legacy_plugin_manager_local import _EngineStub
from tests.test_plugin_legacy_plugin_manager_local import LegacyPluginManagerLocalTests


class LegacySecurityReviewTests(unittest.TestCase):
    def test_legacy_imports_and_constructors_emit_deprecation_warning(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", DeprecationWarning)
            PluginAPI()
            PluginBase()
            sandbox = PluginSandbox()
            PluginManager(plugin_api=None, sandbox=sandbox, engine=_EngineStub())  # type: ignore[arg-type]
            PluginSystemCore()
            PluginMarket()
            asyncio.run(get_categories())
        messages = [str(item.message) for item in caught if issubclass(item.category, DeprecationWarning)]
        self.assertTrue(any("PluginAPI is a deprecated legacy" in message for message in messages))
        self.assertTrue(any("PluginBase is a deprecated legacy" in message for message in messages))
        self.assertTrue(any("PluginManager is a deprecated legacy" in message for message in messages))
        self.assertTrue(any("PluginSandbox is a deprecated legacy" in message for message in messages))
        self.assertTrue(any("PluginSystemCore is a deprecated legacy" in message for message in messages))
        self.assertTrue(any("PluginMarket is a deprecated legacy" in message for message in messages))
        self.assertTrue(any("store_api is a deprecated legacy" in message for message in messages))

    def test_production_legacy_local_load_requires_migration(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            LegacyPluginManagerLocalTests()._write_legacy_plugin(root, required_permissions=[])
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

    def test_legacy_plugin_api_gateway_fallback_is_explicit(self) -> None:
        class _Gateway:
            def __init__(self) -> None:
                self.output: list[tuple[str, str]] = []

            def read_memory(self, key: str) -> str:
                return f"gateway:{key}"

            def send_output(self, content: str, channel: str = "default") -> dict[str, str]:
                self.output.append((content, channel))
                return {"content": content, "channel": channel}

        gateway = _Gateway()
        api = PluginAPI(gateway_client=gateway)
        self.assertEqual(api.memory_retrieve("k"), ["gateway:k"])
        self.assertEqual(api.send_output("hello", "ops"), {"content": "hello", "channel": "ops"})


if __name__ == "__main__":
    unittest.main()
