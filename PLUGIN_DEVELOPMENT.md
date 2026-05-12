# Plugin Development

## Directory Layout

A plugin package should contain:

```text
my_plugin/
  plugin.yaml
  manifest.lock
  src/
    __init__.py
    main.py
  requirements.txt
  requirements.lock
  config_schema.json
  assets/
  tests/
```

`plugin.yaml` and `src/` are required. `manifest.lock` is required for third-party production installs.

## plugin.yaml

Minimal tool plugin:

```yaml
name: hello_world
version: 1.0.0
description: Hello world plugin
author: Example Team
license: MIT
runtime:
  mode: sub_process
  trust: third_party
  memory_mb: 128
  timeout_seconds: 3
  cpu_seconds: 2
extensions:
  - type: tool
    name: run
    entry: src.main:run
permissions:
  - compute: true
requires:
  python: ">=3.11"
  packages: []
```

Plugin names must be lowercase and use letters, numbers, and underscores. Versions must be semantic versions.

## Permissions

Third-party plugins must request permissions in `plugin.yaml` and an admin or user must approve them before enablement.

Common permissions:

- `compute`: local computation.
- `config.read`: read approved configuration.
- `memory.read`: read host-exposed memory.
- `memory.write`: write host-exposed memory.
- `network.outbound`: make Gateway-mediated HTTP requests to approved destinations.
- `fs.read`: read files in the plugin data directory.
- `fs.write`: write files in the plugin data directory.
- `output.send`: send output through host-controlled channels.

Example network permission:

```yaml
permissions:
  - compute: true
  - network.outbound:
      url: "https://api.example.com/v1/*"
      methods: ["GET"]
```

## Tool Extension

```python
def run(args, api):
    city = args.get("city", "Shanghai")
    return {"message": f"Hello {city}"}
```

Tool functions must return JSON-serializable data. For third-party subprocess plugins, host resource access should use `api`.

## Event Listener

```yaml
extensions:
  - type: event_listener
    entry: src.main:on_user_message
    events: ["user.message"]
```

```python
def on_user_message(event, api):
    api.send_output("log", {"seen": event["name"]})
    return {"ok": True}
```

## Local Testing

Build and install:

```bash
plugin-cli build ./my_plugin --output ./dist
plugin-cli install ./dist/hello_world_v1.0.0.zip
plugin-cli approve hello_world --reviewer dev --reason local-test
plugin-cli call hello_world run --args '{"city": "Shanghai"}'
```

Generate supporting artifacts:

```bash
plugin-cli lock ./my_plugin --wheelhouse ./wheelhouse --vendor
plugin-cli sbom ./my_plugin
plugin-cli sign ./dist/hello_world_v1.0.0.zip --private-key publisher.pem --publisher publisher@example.com
```

Run system tests:

```bash
python -m unittest discover -s tests
```

## Common Errors

- Third-party plugins cannot force `in_process`.
- Production install requires Ed25519 signatures and lockfiles.
- Network requests are denied unless both declared and approved.
- Direct socket or `requests` access is not allowed for third-party production plugins; use the Gateway API.
- File access is limited to the plugin data directory.
- Added or changed permissions during upgrade require reapproval.
