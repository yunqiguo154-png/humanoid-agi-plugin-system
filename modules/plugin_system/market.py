from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .compat import warn_legacy_api
from .marketplace import PluginRegistryClient


@dataclass(frozen=True)
class PluginInfo:
    id: str
    name: str
    version: str
    description: str
    author: str
    category: str
    tags: list[str] = field(default_factory=list)
    download_url: str = ""
    size_kb: int = 0
    downloads: int = 0
    rating: float = 0.0
    icon_url: str | None = None
    screenshots: list[str] = field(default_factory=list)
    changelog: str = ""
    dependencies: list[str] = field(default_factory=list)
    min_app_version: str = "1.0.0"
    is_official: bool = False


class PluginMarket:
    """Legacy plugin market compatibility layer.

    The new plugin system installs from signed registry artifacts. This class
    keeps the historical async `PluginMarket` API used by old frontend routes.
    """

    def __init__(
        self,
        market_url: str = "https://plugins.example.com/api",
        *,
        index: str | None = None,
        index_signature: str | None = None,
        index_public_key: str | None = None,
        index_trust_store: str | None = None,
        plugins_dir: str = "data/plugins",
        production_mode: bool = False,
        timeout_seconds: float = 10.0,
        catalog: list[PluginInfo] | None = None,
    ) -> None:
        warn_legacy_api("PluginMarket")
        self.market_url = market_url
        self.index = index
        self.index_signature = index_signature
        self.index_public_key = index_public_key
        self.index_trust_store = index_trust_store
        self.plugins_dir = plugins_dir
        self.production_mode = production_mode
        self.timeout_seconds = timeout_seconds
        self._cache: dict[str, PluginInfo] = {}
        self._catalog = list(catalog) if catalog is not None else _default_catalog()

    def get_categories(self) -> list[dict[str, str]]:
        return list(_default_categories())

    async def fetch_plugins(self, category: str | None = None, search: str | None = None) -> list[PluginInfo]:
        plugins = await self._load_plugins()
        results = plugins
        if category:
            results = [item for item in results if item.category == category]
        if search:
            keyword = search.strip().lower()
            if keyword:
                results = [
                    item
                    for item in results
                    if keyword in item.name.lower()
                    or keyword in item.description.lower()
                    or any(keyword in tag.lower() for tag in item.tags)
                ]
        for plugin in results:
            self._cache[plugin.id] = plugin
        return results

    async def get_plugin_detail(self, plugin_id: str) -> PluginInfo | None:
        cached = self._cache.get(plugin_id)
        if cached is not None:
            return cached
        for plugin in await self._load_plugins():
            if plugin.id == plugin_id:
                self._cache[plugin_id] = plugin
                return plugin
        return None

    async def download_plugin(self, plugin_id: str, save_path: str = "data/plugins") -> bool:
        # Keep legacy method shape, but do secure install through signed registry
        # in modern deployments.
        if not self.index:
            return False
        target = await self.get_plugin_detail(plugin_id)
        version = target.version if target is not None else None
        plugins_dir = save_path or self.plugins_dir
        try:
            PluginRegistryClient(
                self.index,
                index_signature=self.index_signature,
                timeout_seconds=self.timeout_seconds,
            ).install(
                plugin_id,
                plugins_dir=plugins_dir,
                version=version,
                public_key=self.index_public_key,
                trust_store=self.index_trust_store,
                require_signature=True,
                index_public_key=self.index_public_key,
                index_trust_store=self.index_trust_store,
                require_index_signature=self.production_mode,
                production_mode=self.production_mode,
            )
        except Exception:
            return False
        return True

    async def _load_plugins(self) -> list[PluginInfo]:
        if not self.index:
            return list(self._catalog)
        try:
            entries = PluginRegistryClient(
                self.index,
                index_signature=self.index_signature,
                timeout_seconds=self.timeout_seconds,
            ).list_plugins(
                public_key=self.index_public_key,
                trust_store=self.index_trust_store,
                require_signature=self.production_mode,
            )
            plugins = [_from_registry_entry(item) for item in entries]
            if plugins:
                return plugins
        except Exception:
            pass
        return list(self._catalog)


def _from_registry_entry(entry: Any) -> PluginInfo:
    return PluginInfo(
        id=str(entry.name),
        name=str(entry.name),
        version=str(entry.version),
        description=str(entry.description),
        author=str(entry.publisher or "unknown"),
        category="tool",
        tags=[],
        download_url=str(entry.package),
        size_kb=0,
        downloads=0,
        rating=0.0,
        icon_url=None,
        screenshots=[],
        changelog="",
        dependencies=[],
        min_app_version="1.0.0",
        is_official=bool(str(entry.publisher or "").startswith("official")),
    )


def _default_categories() -> tuple[dict[str, str], ...]:
    return (
        {"id": "expert", "name": "专家模型", "icon": "robot", "description": "领域专家插件"},
        {"id": "output", "name": "输出渠道", "icon": "speaker", "description": "语音、图片等输出插件"},
        {"id": "tool", "name": "工具插件", "icon": "tools", "description": "实用工具扩展"},
        {"id": "scene", "name": "场景适配", "icon": "target", "description": "特定场景规则插件"},
        {"id": "memory", "name": "记忆增强", "icon": "brain", "description": "记忆检索/存储增强"},
    )


def _default_catalog() -> list[PluginInfo]:
    return [
        PluginInfo(
            id="calc-expert",
            name="calc_expert",
            version="1.0.0",
            description="计算器专家，处理数学计算问题",
            author="official",
            category="expert",
            tags=["数学", "计算", "公式"],
            download_url="https://plugins.example.com/calc_expert",
            size_kb=256,
            downloads=1250,
            rating=4.8,
            is_official=True,
            changelog="1.0.0 初始版本",
        ),
        PluginInfo(
            id="translate-expert",
            name="translate_expert",
            version="1.2.0",
            description="翻译专家，支持多语言互译",
            author="translation-team",
            category="expert",
            tags=["翻译", "语言", "中英"],
            download_url="https://plugins.example.com/translate_expert",
            size_kb=512,
            downloads=3200,
            rating=4.6,
            changelog="1.2.0 支持更多语言",
        ),
        PluginInfo(
            id="tts-voice",
            name="tts_voice",
            version="0.9.0",
            description="高品质语音合成，支持多种音色",
            author="voice-lab",
            category="output",
            tags=["语音", "TTS", "音色"],
            download_url="https://plugins.example.com/tts_voice",
            size_kb=1024,
            downloads=890,
            rating=4.5,
            changelog="0.9.0 新增3种音色",
        ),
        PluginInfo(
            id="calendar-tool",
            name="calendar_tool",
            version="1.0.0",
            description="日历工具，查询日期、节日",
            author="efficiency-tools",
            category="tool",
            tags=["日历", "日期", "节日"],
            download_url="https://plugins.example.com/calendar_tool",
            size_kb=128,
            downloads=2100,
            rating=4.9,
            changelog="1.0.0 初始版本",
        ),
        PluginInfo(
            id="code-expert",
            name="code_expert",
            version="2.1.0",
            description="代码专家，支持多语言代码生成和调试",
            author="code-lab",
            category="expert",
            tags=["代码", "编程", "Python"],
            download_url="https://plugins.example.com/code_expert",
            size_kb=768,
            downloads=4500,
            rating=4.7,
            is_official=True,
            changelog="2.1.0 支持更多语言",
        ),
    ]
