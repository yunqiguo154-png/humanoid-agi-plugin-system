# Release Notes

## Suggested Version

`v0.9.0-rc3` is the current external acceptance tag.

Do not mark this as `v1.0.0` GA until the external production acceptance items are completed and archived.

## RC Tags

- `v0.9.0-rc1`: local RC freeze point.
- `v0.9.0-rc2`: CI evidence archival and external validation preparation point.
- Post-RC2 `main` added bwrap worker diagnostics, bwrap-internal preflight, local audit verify evidence tooling, and separated GitHub-hosted bwrap diagnostic from target production validation. Do not move `v0.9.0-rc2`.
- `v0.9.0-rc3`: target Linux+bwrap validation evidence alignment point at `b3cddd17ae5f3e51ed40878ae60761ef43e54a63`.
- Current status remains RC, not GA.

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
- GitHub-hosted bwrap diagnostic artifact plus workflow-dispatch self-hosted Linux+bwrap production validation template.
- RC evidence tooling: local evidence collector, local audit verify evidence helper, plus registry, revocation, quarantine, and rollback drill runners.

## Security Boundary

The security boundary for untrusted third-party plugins is OS isolation such as Linux bubblewrap, an external attested sandbox, a container, or a microVM. Python static scanning, monkey patching, and import blocking are defense in depth only.

Plugin output remains untrusted tool result data and must be validated by downstream consumers.

## Known Limits

- Release gate remains NO_GO until real scanner evidence and external audit anchor or accepted risk evidence are archived.
- Windows Job Object is resource limiting only, not complete filesystem/network/syscall isolation.
- Local audit checkpoint files are not immutable audit storage.
- Offline scanner adapters are not real vulnerability intelligence.
- Registry support is signed distribution, not a full public marketplace.
- Real bwrap behavior depends on target Linux kernel, namespace permissions, and deployment configuration.
- GitHub-hosted Ubuntu bwrap diagnostics can fail because hosted runners restrict namespace or loopback operations; this is not production Linux+bwrap pass evidence.
- A target VM previously passed the bwrap backend probe but failed worker/runtime validation. Post-RC2 diagnostics fixed that path; copied VM evidence now shows target Linux+bwrap `production-required` validation passing for rc3 review.

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

Run the next RC tag first on a Linux host class with bubblewrap installed. The copied VM evidence shows bwrap passing
after manual file sync, but final archive should use a real tag/commit checkout. Archive:

- GitHub Actions matrix URL for `v0.9.0-rc3`.
- `acceptance_result.json`.
- Production Doctor JSON.
- `bwrap_validation.json` from `--mode production-required` on a target Linux VM or self-hosted Linux+bwrap runner.
- Optional `bwrap_diagnostic_github_hosted.json` for hosted runner troubleshooting only.
- Preflight and stdio worker diagnostics when target Linux+bwrap validation fails before producing sample JSON.
- Scanner report from the approved scanner.
- Audit checkpoint verification.
- Registry, revocation, emergency quarantine, and rollback drill output.

Copied VM evidence status after the diagnostics patch:

- `bwrap.validation`: pass.
- `registry.verify`, `revocation.drill`, `quarantine.drill`, `rollback.drill`: pass.
- Release Gate: `NO_GO`. After rc3 CI alignment and blocker classification fixes, expected remaining blockers are real scanner evidence and external audit anchor / controlled risk.

## Do Not Claim

- Do not claim Windows third-party production is strongly sandboxed without an external sandbox.
- Do not claim local checkpoints are immutable audit logs.
- Do not claim offline fixture scanners provide real vulnerability coverage.
- Do not claim the registry client is a complete public marketplace.
- Do not claim GitHub-hosted bwrap diagnostic output is target Linux+bwrap production validation.

## v1.0 GA Exit Criteria

- Hosted CI matrix results archived.
- Target Linux+bwrap validation passes on production host classes.
- Real vulnerability and license scanner integrated.
- External append-only audit anchor integrated.
- Security and operations sign off on accepted risks.
