# Release Notes

## Suggested Version

`v0.9.0-rc1`

Do not mark this as `v1.0.0` GA until the external production acceptance items are completed and archived.

## Current Capability

- Legacy plugin compatibility shims are deprecated and emit `DeprecationWarning`.
- Legacy local `plugins/<name>/metadata.json + plugin.py` loading is development-only and raises `MigrationRequiredError` in production mode.
- Production mode with third-party subprocess execution and fail-closed policy.
- Default `PolicyEngine` enforcement in production `PluginEngine`.
- Ed25519 package signatures and signed registry indexes.
- HMAC retained only for legacy/development compatibility.
- Manifest lockfile, SBOM, dependency policy, and scanner report checks.
- Gateway-mediated memory, file, network, event, and output access.
- Network SSRF, metadata service, redirect, and DNS rebinding protections.
- Linux-first bubblewrap backend and validation harness.
- JSONL audit hash chain with checkpoint anchor interface.
- Disable, quarantine, revoke, revoked key, and revoked plugin version controls.
- CI workflow for Linux/Windows and Python 3.11/3.12/3.13.
- RC evidence tooling: local evidence collector plus registry, revocation, quarantine, and rollback drill runners.

## Security Boundary

The security boundary for untrusted third-party plugins is OS isolation such as Linux bubblewrap, an external attested sandbox, a container, or a microVM. Python static scanning, monkey patching, and import blocking are defense in depth only.

Plugin output remains untrusted tool result data and must be validated by downstream consumers.

## Known Limits

- RC-1 release gate remains NO_GO until external CI, target Linux+bwrap, real scanner, external audit anchor, and required drill evidence are archived.
- Windows Job Object is resource limiting only, not complete filesystem/network/syscall isolation.
- Local audit checkpoint files are not immutable audit storage.
- Offline scanner adapters are not real vulnerability intelligence.
- Registry support is signed distribution, not a full public marketplace.
- Real bwrap behavior depends on target Linux kernel, namespace permissions, and deployment configuration.

## Upgrade Notes

- Production installs now require SBOM and passing scan report by default for third-party plugins.
- CLI `policy check` accepts signature and scan evidence for production checks.
- Release approval should use `scripts/run_production_acceptance.py` and `scripts/release_gate.py`.

## Rollback

1. Quarantine affected plugin.
2. Stop running plugin sandbox.
3. Revoke plugin version or signer key if trust is compromised.
4. Reinstall the previous signed package.
5. Verify audit hash chain and checkpoint.
6. Archive incident evidence.

## Production Pilot Recommendation

Run RC-1 first on a Linux host class with bubblewrap installed. Archive:

- GitHub Actions matrix URL.
- `acceptance_result.json`.
- Production Doctor JSON.
- bwrap validation JSON.
- Scanner report from the approved scanner.
- Audit checkpoint verification.
- Registry, revocation, emergency quarantine, and rollback drill output.

## Do Not Claim

- Do not claim Windows third-party production is strongly sandboxed without an external sandbox.
- Do not claim local checkpoints are immutable audit logs.
- Do not claim offline fixture scanners provide real vulnerability coverage.
- Do not claim the registry client is a complete public marketplace.

## v1.0 GA Exit Criteria

- Hosted CI matrix results archived.
- Target Linux+bwrap validation passes on production host classes.
- Real vulnerability and license scanner integrated.
- External append-only audit anchor integrated.
- Security and operations sign off on accepted risks.
