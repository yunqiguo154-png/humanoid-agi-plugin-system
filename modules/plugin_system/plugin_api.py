from __future__ import annotations

from typing import Any

from .compat import warn_legacy_api


class PluginAPI:
    """Legacy plugin API compatibility wrapper.

    This preserves the historical method surface used by older plugins while
    allowing optional forwarding to the new gateway client.
    """

    def __init__(
        self,
        memory_module: Any = None,
        output_system: Any = None,
        adaptive_system: Any = None,
        *,
        gateway_client: Any = None,
    ) -> None:
        warn_legacy_api("PluginAPI")
        self._memory_module = memory_module
        self._output_system = output_system
        self._adaptive_system = adaptive_system
        self._gateway_client = gateway_client
        self._plugin_context: dict[str, Any] = {}

    def get_current_context(self) -> list[dict[str, str]]:
        if self._memory_module and hasattr(self._memory_module, "get_context"):
            context = self._memory_module.get_context()
            return context if isinstance(context, list) else []
        return []

    def memory_retrieve(self, query: str, top_k: int = 3) -> list[str]:
        if self._memory_module and hasattr(self._memory_module, "retrieve"):
            result = self._memory_module.retrieve(query, top_k)
            return self._normalize_string_list(result)
        if self._gateway_client and hasattr(self._gateway_client, "read_memory"):
            value = self._gateway_client.read_memory(query)
            if value is None:
                return []
            if isinstance(value, list):
                return self._normalize_string_list(value)
            return [str(value)]
        return []

    def memory_store(self, key: str, value: Any) -> None:
        self._plugin_context[key] = value

    def get_plugin_context(self, key: str) -> Any:
        return self._plugin_context.get(key)

    def clear_plugin_context(self) -> None:
        self._plugin_context.clear()

    def send_output(self, content: str, channel: str = "console") -> Any:
        if self._output_system and hasattr(self._output_system, "process"):
            return self._output_system.process(
                raw_content=content,
                input_context={},
                channel=channel,
                stream=False,
            )
        if self._gateway_client and hasattr(self._gateway_client, "send_output"):
            return self._gateway_client.send_output(content, channel=channel)
        return None

    def get_current_strategy(self) -> dict[str, Any]:
        if self._adaptive_system and hasattr(self._adaptive_system, "get_current_status"):
            status = self._adaptive_system.get_current_status()
            if isinstance(status, dict):
                strategy = status.get("current_strategy", {})
                return strategy if isinstance(strategy, dict) else {}
        return {}

    def _normalize_string_list(self, value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(item) for item in value]
