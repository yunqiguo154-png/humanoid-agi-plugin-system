from __future__ import annotations

import unittest

from modules.plugin_system.plugin_api import PluginAPI


class _MemoryStub:
    def get_context(self) -> list[dict[str, str]]:
        return [{"role": "user", "content": "hello"}]

    def retrieve(self, query: str, top_k: int) -> list[str]:
        return [f"{query}:{top_k}"]


class _OutputStub:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def process(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(dict(kwargs))
        return {"ok": True}


class _AdaptiveStub:
    def get_current_status(self) -> dict[str, object]:
        return {"current_strategy": {"name": "balanced"}}


class _GatewayStub:
    def __init__(self) -> None:
        self.memory: dict[str, object] = {"city": "beijing"}
        self.output_calls: list[tuple[str, str]] = []

    def read_memory(self, key: str) -> object | None:
        return self.memory.get(key)

    def send_output(self, content: str, channel: str = "default") -> dict[str, object]:
        self.output_calls.append((content, channel))
        return {"channel": channel, "content": content}


class LegacyPluginApiTests(unittest.TestCase):
    def test_legacy_plugin_api_surface_preserved(self) -> None:
        memory = _MemoryStub()
        output = _OutputStub()
        adaptive = _AdaptiveStub()
        api = PluginAPI(memory_module=memory, output_system=output, adaptive_system=adaptive)

        self.assertEqual(api.get_current_context(), [{"role": "user", "content": "hello"}])
        self.assertEqual(api.memory_retrieve("weather", 2), ["weather:2"])

        api.memory_store("foo", {"bar": 1})
        self.assertEqual(api.get_plugin_context("foo"), {"bar": 1})
        api.clear_plugin_context()
        self.assertIsNone(api.get_plugin_context("foo"))

        api.send_output("hello", channel="console")
        self.assertEqual(output.calls[-1]["raw_content"], "hello")
        self.assertEqual(output.calls[-1]["channel"], "console")
        self.assertFalse(bool(output.calls[-1]["stream"]))
        self.assertEqual(api.get_current_strategy(), {"name": "balanced"})

    def test_gateway_fallback_works_when_legacy_modules_absent(self) -> None:
        gateway = _GatewayStub()
        api = PluginAPI(gateway_client=gateway)

        self.assertEqual(api.memory_retrieve("city"), ["beijing"])
        response = api.send_output("ok", channel="ops")
        self.assertEqual(response, {"channel": "ops", "content": "ok"})
        self.assertEqual(gateway.output_calls[-1], ("ok", "ops"))
        self.assertEqual(api.get_current_context(), [])
        self.assertEqual(api.get_current_strategy(), {})


if __name__ == "__main__":
    unittest.main()
