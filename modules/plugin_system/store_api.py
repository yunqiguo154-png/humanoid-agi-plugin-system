from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any

from .compat import warn_legacy_api
from .market import PluginInfo, PluginMarket

try:
    from fastapi import APIRouter, HTTPException, Query
    from pydantic import BaseModel, Field as PydanticField

    FASTAPI_AVAILABLE = True
    Field = PydanticField
except Exception as exc:  # pragma: no cover - fallback for environments without fastapi
    APIRouter = None  # type: ignore[assignment]
    HTTPException = RuntimeError  # type: ignore[assignment]
    FASTAPI_AVAILABLE = False
    FASTAPI_IMPORT_ERROR = exc

    def Query(default: Any = None, **_: Any) -> Any:  # type: ignore[misc]
        return default

    def _fallback_field(
        default: Any = None,
        *,
        default_factory: Any | None = None,
        **_: Any,
    ) -> Any:  # type: ignore[misc]
        if default_factory is not None:
            return default_factory()
        return default
    Field = _fallback_field

    class BaseModel:  # type: ignore[no-redef]
        pass
else:
    FASTAPI_IMPORT_ERROR = None


router = APIRouter(prefix="/plugin-store", tags=["插件商店"]) if APIRouter is not None else None
_market = PluginMarket()


class PluginDetailResponse(BaseModel):
    id: str
    name: str
    version: str
    description: str
    author: str
    category: str
    tags: list[str]
    size_kb: int
    downloads: int
    rating: float
    icon_url: str | None = None
    screenshots: list[str] = Field(default_factory=list)
    changelog: str
    dependencies: list[str] = Field(default_factory=list)
    min_app_version: str
    is_official: bool


class PluginInstallRequest(BaseModel):
    plugin_id: str


def set_market_instance(market: PluginMarket) -> None:
    global _market
    _market = market


def get_market_instance() -> PluginMarket:
    return _market


def _serialize_plugin(plugin: PluginInfo) -> dict[str, Any]:
    if is_dataclass(plugin):
        payload = asdict(plugin)
        if isinstance(payload, dict):
            return payload
    if hasattr(plugin, "__dict__"):
        return dict(plugin.__dict__)
    raise TypeError("plugin info is not serializable")


async def get_categories() -> dict[str, Any]:
    warn_legacy_api("store_api")
    return {"success": True, "data": _market.get_categories()}


async def get_plugins(
    category: str | None = Query(None, description="插件分类"),
    search: str | None = Query(None, description="搜索关键词"),
    sort: str | None = Query("downloads", description="排序字段: downloads/rating/newest"),
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(20, ge=1, le=50, description="每页数量"),
) -> dict[str, Any]:
    warn_legacy_api("store_api")
    if not isinstance(category, str):
        category = None
    if not isinstance(search, str):
        search = None
    if not isinstance(sort, str):
        sort = "downloads"
    plugins = await _market.fetch_plugins(category, search)
    if sort == "rating":
        plugins.sort(key=lambda item: item.rating, reverse=True)
    elif sort == "newest":
        plugins.sort(key=lambda item: item.version, reverse=True)
    else:
        plugins.sort(key=lambda item: item.downloads, reverse=True)

    total = len(plugins)
    start = (page - 1) * page_size
    end = start + page_size
    paginated = plugins[start:end]
    return {
        "success": True,
        "data": {
            "plugins": [_serialize_plugin(item) for item in paginated],
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
        },
    }


async def get_plugin_detail(plugin_id: str) -> dict[str, Any]:
    warn_legacy_api("store_api")
    plugin = await _market.get_plugin_detail(plugin_id)
    if plugin is None:
        raise HTTPException(status_code=404, detail="插件不存在")
    return {"success": True, "data": _serialize_plugin(plugin)}


async def install_plugin(request: PluginInstallRequest) -> dict[str, Any]:
    warn_legacy_api("store_api")
    success = await _market.download_plugin(request.plugin_id)
    if not success:
        raise HTTPException(status_code=500, detail="插件安装失败")
    return {"success": True, "message": "插件安装成功，请在插件管理中启用"}


async def get_recommended_plugins() -> dict[str, Any]:
    warn_legacy_api("store_api")
    plugins = await _market.fetch_plugins()
    recommended = sorted(plugins, key=lambda item: item.downloads * item.rating, reverse=True)[:5]
    return {"success": True, "data": [_serialize_plugin(item) for item in recommended]}


async def get_official_plugins() -> dict[str, Any]:
    warn_legacy_api("store_api")
    plugins = await _market.fetch_plugins()
    official = [item for item in plugins if item.is_official]
    return {"success": True, "data": [_serialize_plugin(item) for item in official]}


if router is not None:
    router.add_api_route("/categories", get_categories, methods=["GET"])
    router.add_api_route("/plugins", get_plugins, methods=["GET"])
    router.add_api_route("/plugin/{plugin_id}", get_plugin_detail, methods=["GET"])
    router.add_api_route("/install", install_plugin, methods=["POST"])
    router.add_api_route("/recommend", get_recommended_plugins, methods=["GET"])
    router.add_api_route("/official", get_official_plugins, methods=["GET"])
