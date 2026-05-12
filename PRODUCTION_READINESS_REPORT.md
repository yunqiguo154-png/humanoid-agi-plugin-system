# Production Readiness Report

## Current Capability Overview

The plugin system has a production-grade foundation for controlled plugin execution:

- Loader, Engine, SandboxManager, Gateway, EventBus, Registry client, signing, SBOM, dependency policy, and audit modules.
- Production mode for third-party subprocess execution, signature enforcement, enforced sandbox requirement, and fail-closed behavior.
- Linux-first bubblewrap backend.
- Gateway-enforced resource access and network SSRF protections.
- Supply-chain controls for safe extraction, lockfiles, hashes, signatures, registry index signatures, revocation, and SBOM.
- Governance controls for disable, quarantine, revoke, revoked versions, and lifecycle status transitions.
- JSONL audit with hash chain and local checkpoint anchor interfaces.
- CI workflow covering Linux and Windows across Python 3.11, 3.12, and 3.13.

## Test Result Summary

Local validation command:

```bash
python -m unittest discover -s tests
```

Expected result at this stage:

```text
142+ tests OK, with platform-dependent skips for OS sandbox integration.
```

The exact count may increase as enterprise readiness tests are added. bwrap integration tests skip when Linux or `bwrap` is unavailable; fail-closed policy tests do not skip.

## Security Boundary

The production security boundary for third-party plugins is OS-level isolation: Linux bubblewrap, an external attested sandbox, a container, or a microVM. Python monkey patching, AST scanning, import blocking, and disabled `eval/exec` are defense in depth only.

Plugin output is untrusted data and must be validated before display, storage, tool use, or onward transmission.

## Production Mode Behavior

Production mode requires:

- Third-party plugins run out of process.
- Enforced sandbox backend.
- Ed25519 signatures.
- Signed registry indexes.
- Fail-closed startup when sandbox enforcement is unavailable.
- Permission review for third-party plugins and reapproval on permission expansion.

## Linux Sandbox Deployment Requirements

Linux deployments should install `bubblewrap` and run:

```bash
plugin-cli doctor --production --json
python scripts/validate_bwrap_sandbox.py --json
```

The validation harness attempts host HOME reads, `.env` reads, project core reads, plugin code writes, direct network access, process escape attempts, file churn, and large output behavior.

## Windows Limitations

Windows Job Object support limits resources but does not provide full filesystem isolation, network isolation, or syscall filtering. Windows third-party production requires an external sandbox, container, or VM with explicit attestation.

## Registry Boundary

The registry implementation is a signed distribution client. It verifies signed indexes, package hashes, signatures, revoked keys, revoked plugin versions, and rollback controls. It is not a complete public plugin marketplace with publisher onboarding, malware review, billing, reputation, or abuse operations.

## Audit Capability

Local audit logs use JSON Lines with a hash chain. Local checkpoint anchors detect truncation and rollback when the checkpoint is preserved separately. This is not a substitute for append-only storage. Production should anchor logs into SIEM, WORM buckets, transparency logs, or centrally managed append-only systems.

## Supply Chain Capability

Current controls include:

- Safe zip extraction.
- Manifest lockfile and file hash verification.
- Dependency lockfile policy and local wheelhouse path.
- Ed25519 signatures.
- HMAC legacy/dev restriction.
- Registry signature and revocation support.
- CycloneDX SBOM generation.
- Offline scanner adapter interfaces and fixture scanners.

## Completed Enterprise Additions

- Production Doctor.
- Linux bwrap validation harness.
- AuditSink and checkpoint anchor interfaces.
- Local checkpoint anchor with optional Ed25519 signature.
- Offline vulnerability and license scanner adapters.
- Organization policy engine.
- CI workflow self-check tests.
- CI readiness documentation.
- Risk register.

## Remaining Enterprise Gaps

- Real CI matrix results must be reviewed from GitHub Actions.
- Production audit anchoring must be integrated with a real append-only service.
- Real vulnerability/license scanners must be connected.
- bwrap behavior must be validated on the actual production Linux host.
- Windows requires external strong isolation.
- Operational RBAC and admin identity integration are still deployment responsibilities.

## Launch Acceptance Steps

1. Run CI and verify all matrix jobs pass.
2. Run `plugin-cli doctor --production --json` on target hosts.
3. Run `python scripts/validate_bwrap_sandbox.py --json` on Linux production hosts.
4. Verify registry index signature and revocation data.
5. Verify signing key custody and key revocation process.
6. Generate SBOMs and scanner reports for all plugins.
7. Verify audit forwarding and checkpoint anchoring.
8. Run incident drills for disable, quarantine, revoke plugin, revoke version, and revoke signer key.

## Rollback Strategy

- Disable or quarantine the affected plugin immediately.
- Stop running plugin sandboxes.
- Revoke affected plugin version in governance/registry metadata.
- Reinstall last known-good signed package if needed.
- Verify audit log and checkpoint continuity.
- Review Gateway network and capability audit events for impact.

## Emergency Disable Flow

```bash
plugin-cli quarantine plugin_name
plugin-cli revoke-version plugin_name 1.2.3
plugin-cli trust --store trust-store.json revoke-key publisher@example.com key_id
plugin-cli audit verify --log data/plugins/audit.log
```

Quarantine should stop a running plugin and prevent subsequent calls.
