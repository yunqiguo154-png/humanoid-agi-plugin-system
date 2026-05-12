# Supply Chain Security

## Package Signing

Production trust requires Ed25519 signatures. HMAC is retained only for legacy and development compatibility and must not be treated as production trust.

Create an Ed25519 key pair:

```bash
plugin-cli keygen --private-key publisher-private.pem --public-key publisher-public.pem
```

Sign a package:

```bash
plugin-cli sign dist/plugin_v1.0.0.zip --private-key publisher-private.pem --publisher publisher@example.com
```

Verify:

```bash
plugin-cli verify dist/plugin_v1.0.0.zip --public-key publisher-public.pem
```

## Lockfiles And Hashes

`manifest.lock` records hashes for package files. Production third-party installs require it. Install and startup verification reject changed, missing, extra, or mismatched locked files.

Dependency lockfiles must pin wheels with hashes. Production installs reject unlocked dependencies and must not fetch arbitrary runtime dependencies from the public internet.

## Safe Package Installation

The installer rejects:

- Zip slip paths.
- Absolute paths.
- Path traversal.
- Symlink and special-file archive members.
- Suspicious compression ratios.
- Oversized archives and files.
- Excessive file counts.
- Package hash mismatches.

## SBOM

Generate a CycloneDX JSON SBOM:

```bash
plugin-cli sbom ./my_plugin
```

The SBOM records plugin name, version, file hashes, dependencies, dependency versions, and dependency hashes when available.

## Dependency Scanning

The dependency layer has adapter interfaces for vulnerability and license scanners. The current project does not require live network scanning in tests. Production deployments should connect approved scanners and fail closed on scanner policy failure.

Native extensions are high risk. The default production policy should reject or require high-trust approval for native wheels and packages that need arbitrary build execution.

Offline fixture scanners are available for tests and integration dry runs:

```bash
plugin-cli scan sbom sbom.cdx.json --json
plugin-cli scan package plugin_v1.0.0.zip --json
plugin-cli scan lock requirements.lock --json
```

These commands do not call OSV, PyPI, GitHub Advisory, or any external API. They are adapter surfaces for production scanner integration.

## Registry Integrity

Production registry indexes must be signed. Each entry must include package `sha256`. Registry policy prevents downgrade and same-version replacement unless explicitly allowed outside production.

The registry supports:

- Revoked publisher keys.
- Revoked plugin versions.
- Publisher identity checks.
- Package hash verification.
- Signed index verification.

The local registry client is not a complete public marketplace. It does not provide automated publisher onboarding, malware review, reputation, billing, or abuse operations.

## Revocation

Use revocation when a signer key, plugin version, or installed plugin should no longer be trusted:

```bash
plugin-cli trust --store trust-store.json revoke-key publisher@example.com <key_id>
plugin-cli revoke-version plugin_name 1.0.0
plugin-cli revoke plugin_name
```

Production deployments should distribute revocation data through signed registry metadata and operational governance state.
