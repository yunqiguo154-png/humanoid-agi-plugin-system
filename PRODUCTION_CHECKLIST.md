# Production Checklist

## Required Before Launch

- Enable `production_mode=True` for production plugin runtime.
- Run `plugin-cli doctor --production --json` on production-like hosts and resolve production-blocking findings.
- Run `python scripts/validate_bwrap_sandbox.py --json` on Linux hosts that will execute third-party plugins.
- Run all third-party plugins out of process.
- Require an enforced sandbox backend for third-party plugins.
- On Linux, install and validate `bubblewrap`.
- Reject startup when sandbox enforcement is unavailable.
- Require Ed25519 package signatures.
- Require signed registry indexes.
- Require `manifest.lock` and dependency hash pinning.
- Route all network access through the Gateway.
- Approve permissions before enablement and reapprove added or changed permissions.
- Store audit logs in centralized append-only storage.
- Configure audit checkpoint anchoring outside the plugin host trust boundary.
- Verify audit hash chains during operations.
- Connect vulnerability and license scanner adapters to production scanning infrastructure.
- Document incident handling for disable, quarantine, revoke plugin, revoke version, and revoke signer key.

## Recommended Before Launch

- Run CI on Linux and Windows for all supported Python versions.
- Add external vulnerability scanning for dependencies.
- Add license scanning.
- Add malware/static analysis for plugin packages.
- Use a private package/wheelhouse source.
- Run Linux OS sandbox integration tests on at least one runner with `bwrap`.
- Forward audit logs to SIEM.
- Add alerting for sandbox denials, network denials, revocations, and repeated plugin failures.
- Store signing keys in a hardware-backed or managed key service.

## Known Limits

- Python monkey patching, AST scanning, and import blocking are not strong isolation.
- `python_guard` is not a production sandbox for untrusted plugins.
- Windows Job Object support limits resources but does not provide complete filesystem, network, or syscall isolation.
- Local audit hash chains detect modification but do not prevent full log deletion or rollback.
- The registry client is a signed distribution mechanism, not a complete public marketplace.
- External scanner adapters are present, but scanner infrastructure must be supplied by deployment.

## Platform Support Matrix

| Platform | Runtime support | Strong third-party sandbox status | Notes |
| --- | --- | --- | --- |
| Linux + bwrap | Supported | Preferred production path | Fails closed if bwrap is missing or unusable. |
| Linux without bwrap | Development only for third-party plugins | Not production-ready | Production third-party startup must fail closed. |
| Windows | Supported with Job Object resource limits | Not equivalent to strong sandbox | Requires external attested sandbox for production third-party plugins. |
| macOS | Development compatibility | No built-in strong backend | Requires external sandbox/container strategy. |

## Security Test Matrix

| Area | Expected coverage |
| --- | --- |
| Production policy | Third-party plugins cannot run in process; missing enforced sandbox fails closed. |
| OS sandbox | Linux bwrap integration blocks host HOME, `.env`, project core reads, code writes, and direct network when bwrap is available. |
| Gateway network | Rejects unauthorized hosts, localhost, private/link-local ranges, metadata service, unsafe userinfo, unsafe redirects, and DNS rebinding. |
| Supply chain | Rejects zip slip, archive bombs, large files, unsigned packages, HMAC in production, revoked keys, revoked versions, and lockfile hash mismatch. |
| Governance | Disabled, quarantined, and revoked plugins cannot start; illegal status transitions are rejected and audited. |
| Audit | JSONL records include governance fields; hash chain verifies; tampering is detected. |

## CI Expectations

The GitHub Actions workflow runs:

- Python 3.11, 3.12, and 3.13.
- Linux and Windows.
- `python -m ruff check .`
- `python -m mypy`
- `python -m unittest discover -s tests`
- `python -m coverage run -m unittest discover -s tests`
- `python -m coverage report`

Linux bwrap integration tests skip when the platform or executable is unavailable. Production fail-closed policy tests do not skip.
