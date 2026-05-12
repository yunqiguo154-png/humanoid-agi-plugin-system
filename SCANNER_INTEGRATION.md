# Scanner Integration

## Current Scope

`OfflineVulnerabilityScanner` and `OfflineLicenseScanner` are adapter fixtures for tests, CI dry runs, and scanner contract validation. They do not query OSV, PyPI, GitHub Advisory, NVD, vendor feeds, or enterprise SCA systems. They must not be treated as real vulnerability intelligence.

## Production Integration Options

Production deployments should connect one or more approved scanners through the scanner adapter contract:

- OSV scanner or OSV-backed internal service.
- `pip-audit`.
- Safety.
- Syft/Grype.
- Enterprise SCA platforms.
- Internal license-compliance services.

The scanner can run in CI, registry ingestion, or controlled install pipelines. Runtime dependency fetching from the public internet remains disallowed for production third-party plugins.

## Input Contract

Scanner adapters should support at least one of:

- CycloneDX SBOM JSON.
- Plugin package path.
- Dependency lockfile path.

## ScanReport JSON Shape

```json
{
  "scanner_name": "example-sca",
  "scanner_version": "2026.05.11",
  "generated_at": "2026-05-11T00:00:00+00:00",
  "findings": [
    {
      "type": "vulnerability",
      "package": "example",
      "version": "1.0.0",
      "id": "CVE-0000-0000",
      "severity": "high",
      "description": "Example finding",
      "recommendation": "Upgrade or remove",
      "source": "scanner-feed"
    }
  ],
  "severity_summary": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "unknown": 0
  },
  "policy_decision": "pass",
  "reason": "no blocking findings"
}
```

## Policy

Production policy should require `policy_decision=pass` before install or enable. Current policy rejects missing, failed, unknown-scanner, invalid, and expired reports. The default freshness window is 24 hours unless deployment policy changes it.

Recommended production defaults:

- Critical vulnerability: fail.
- High vulnerability: fail unless a time-bound risk acceptance exists.
- Denied license: fail.
- Unknown license: warn or fail by policy.
- Native extension: fail or require high-trust review.

## CI Usage

Run scanner jobs before signing or publishing packages. Archive the scanner JSON report and pass it into install or policy checks:

```bash
plugin-cli scan sbom sbom.cdx.json --json > scan-report.json
plugin-cli --production policy check dist/plugin.zip \
  --signature dist/plugin.zip.sig \
  --trust-store trust-store.json \
  --scan-report scan-report.json \
  --json
```

The built-in offline command is a contract check. Replace it with a production scanner report before release approval.
