# Plugin Migration Guide

## Status

The legacy plugin APIs are compatibility shims. They are deprecated and emit `DeprecationWarning`.

Deprecated APIs include:

- `PluginAPI`
- `PluginBase`
- `PluginManager`
- `PluginSandbox`
- `PluginSystemCore`
- `PluginMarket`
- `store_api`

## Production Limit

The old local plugin layout:

```text
plugins/<name>/metadata.json
plugins/<name>/plugin.py
```

is only supported for development and legacy compatibility. In production mode, this path is rejected with `MigrationRequiredError`. Do not use legacy `importlib` loading for third-party production plugins.

## Required Production Path

Migrate plugins to:

- `plugin.yaml` metadata.
- Declared tool/event/middleware extensions.
- Ed25519 package signature.
- Signed registry distribution.
- `manifest.lock`.
- `requirements.lock` when dependencies exist.
- SBOM.
- Passing scanner report.
- Permission approval through the current engine/loader/policy flow.
- Runtime access through `PluginGateway`.

## Compatibility Notes

The legacy `PluginSandbox` resource checks are not a security boundary. They are best-effort development compatibility only. Production isolation must use OS sandboxing such as Linux bubblewrap, an external attested sandbox, a container, or a microVM.

Legacy `PluginAPI` memory/output compatibility can forward to a gateway client when explicitly provided. Direct access to host modules should not be used by production plugins.

Legacy `PluginMarket` and `store_api` are frontend compatibility wrappers. Production installation must still use signed registry and package verification.
