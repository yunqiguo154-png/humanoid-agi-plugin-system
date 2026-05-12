from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from modules.plugin_system.market import PluginInfo, PluginMarket
from modules.plugin_system.store_api import (
    FASTAPI_AVAILABLE,
    PluginInstallRequest,
    get_categories,
    get_official_plugins,
    get_plugin_detail,
    get_plugins,
    get_recommended_plugins,
    install_plugin,
    router,
    set_market_instance,
)


class LegacyPluginMarketTests(unittest.TestCase):
    def test_market_categories_filter_search_and_detail(self) -> None:
        market = PluginMarket(
            catalog=[
                PluginInfo(
                    id="hello",
                    name="Hello",
                    version="1.0.0",
                    description="hello tool",
                    author="official",
                    category="tools",
                    tags=["example"],
                    size_kb=1,
                    downloads=10,
                    rating=4.5,
                    changelog="",
                    dependencies=[],
                    min_app_version="0.0.0",
                    is_official=True,
                ),
                PluginInfo(
                    id="weather",
                    name="Weather Expert",
                    version="1.1.0",
                    description="weather query",
                    author="community",
                    category="tools",
                    tags=["weather"],
                    size_kb=2,
                    downloads=5,
                    rating=4.0,
                    changelog="",
                    dependencies=[],
                    min_app_version="0.0.0",
                    is_official=False,
                ),
            ]
        )
        categories = market.get_categories()
        self.assertIsInstance(categories, list)
        self.assertIn("expert", {item["id"] for item in categories})
        filtered = asyncio.run(market.fetch_plugins(category="tools", search="weather"))
        self.assertEqual([item.id for item in filtered], ["weather"])
        detail = asyncio.run(market.get_plugin_detail("hello"))
        self.assertIsNotNone(detail)
        assert detail is not None
        self.assertEqual(detail.name, "Hello")
        missing = asyncio.run(market.get_plugin_detail("missing"))
        self.assertIsNone(missing)

    def test_market_download_returns_false_without_index(self) -> None:
        market = PluginMarket(index=None)
        self.assertFalse(asyncio.run(market.download_plugin("hello_world")))

    def test_market_listing_failure_falls_back_to_catalog(self) -> None:
        fallback = [
            PluginInfo(
                id="fallback",
                name="Fallback",
                version="1.0.0",
                description="fallback",
                author="official",
                category="tools",
                tags=[],
                size_kb=1,
                downloads=1,
                rating=1.0,
                changelog="",
                dependencies=[],
                min_app_version="0.0.0",
                is_official=True,
            )
        ]
        market = PluginMarket(index="registry/index.json", catalog=fallback)
        with patch("modules.plugin_system.market.PluginRegistryClient") as client:
            client.return_value.list_plugins.side_effect = RuntimeError("registry offline")
            plugins = asyncio.run(market.fetch_plugins())
        self.assertEqual([item.id for item in plugins], ["fallback"])


class _StoreMarketStub:
    def __init__(self) -> None:
        self.plugins = [
            PluginInfo(
                id="a",
                name="A",
                version="1.0.0",
                description="plugin a",
                author="official",
                category="tools",
                tags=[],
                size_kb=1,
                downloads=10,
                rating=5.0,
                changelog="",
                dependencies=[],
                min_app_version="0.0.0",
                is_official=True,
            ),
            PluginInfo(
                id="b",
                name="B",
                version="1.0.1",
                description="plugin b",
                author="community",
                category="agent",
                tags=[],
                size_kb=1,
                downloads=3,
                rating=4.0,
                changelog="",
                dependencies=[],
                min_app_version="0.0.0",
                is_official=False,
            ),
        ]
        self.install_ok = True

    def get_categories(self) -> list[str]:
        return ["all", "tools", "agent"]

    async def fetch_plugins(self, category: str | None = None, search: str | None = None) -> list[PluginInfo]:
        items = list(self.plugins)
        if category and category != "all":
            items = [item for item in items if item.category == category]
        if search:
            keyword = search.lower()
            items = [item for item in items if keyword in item.name.lower() or keyword in item.description.lower()]
        return items

    async def get_plugin_detail(self, plugin_id: str) -> PluginInfo | None:
        for item in self.plugins:
            if item.id == plugin_id:
                return item
        return None

    async def download_plugin(self, plugin_id: str) -> bool:
        return self.install_ok and any(item.id == plugin_id for item in self.plugins)


class LegacyStoreApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.market = _StoreMarketStub()
        set_market_instance(self.market)  # type: ignore[arg-type]

    def test_store_router_is_available_when_fastapi_installed(self) -> None:
        if FASTAPI_AVAILABLE:
            self.assertIsNotNone(router)
        else:
            self.assertIsNone(router)

    def test_store_list_and_recommend_and_official(self) -> None:
        categories = asyncio.run(get_categories())
        self.assertTrue(categories["success"])
        self.assertEqual(categories["data"], ["all", "tools", "agent"])

        listing = asyncio.run(get_plugins(sort="downloads", page=1, page_size=1))
        self.assertTrue(listing["success"])
        self.assertEqual(listing["data"]["plugins"][0]["id"], "a")
        self.assertEqual(listing["data"]["total_pages"], 2)

        recommended = asyncio.run(get_recommended_plugins())
        self.assertEqual(recommended["data"][0]["id"], "a")
        official = asyncio.run(get_official_plugins())
        self.assertEqual([item["id"] for item in official["data"]], ["a"])

    def test_store_detail_and_install_error_path(self) -> None:
        detail = asyncio.run(get_plugin_detail("a"))
        self.assertTrue(detail["success"])
        self.assertEqual(detail["data"]["id"], "a")

        self.market.install_ok = False
        with self.assertRaises(Exception):
            asyncio.run(install_plugin(PluginInstallRequest(plugin_id="a")))


if __name__ == "__main__":
    unittest.main()
