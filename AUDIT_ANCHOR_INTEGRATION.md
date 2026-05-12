# Audit Anchor Integration

## Current Scope

The local audit sink writes JSON Lines with a hash chain. `LocalCheckpointAnchor` stores the latest sequence and hash in a local JSON file and can optionally sign the checkpoint with Ed25519.

This is tamper-evident, not tamper-proof. If an administrator or attacker can delete, replace, or roll back both the audit log and local checkpoint, local verification cannot prove continuity.

## Production Anchor Options

Production deployments should anchor checkpoints outside the plugin host trust boundary:

- Append-only object storage.
- WORM bucket or immutable retention policy.
- SIEM or centralized log pipeline.
- Transparency log.
- External timestamping service.
- Enterprise audit service with retention controls.

## Checkpoint JSON Shape

```json
{
  "latest_sequence": 123,
  "latest_hash": "64-character-sha256",
  "timestamp": "2026-05-11T00:00:00+00:00",
  "audit_log_path": "/var/log/humanoid_agi/plugin-audit.jsonl",
  "signer": "audit-anchor-prod",
  "key_id": "ed25519-key-id",
  "signature": "base64-ed25519-signature",
  "signature_encoding": "base64"
}
```

## Signing And Key Rotation

Use Ed25519 checkpoint signatures when possible. Keep checkpoint signing keys separate from plugin package signing keys. Rotation should preserve verification of old checkpoints by retaining historical public keys and revocation metadata.

If a checkpoint signing key is revoked, security operations must determine whether existing checkpoints signed by that key remain trusted for their time window or require incident review.

## Recovery Flow

1. Pull audit log and latest external checkpoint.
2. Run audit verification with checkpoint.
3. If verification fails, quarantine affected plugins and freeze logs.
4. Compare with SIEM/WORM/centralized copies.
5. Reconstruct trusted timeline from the append-only source.
6. Rotate keys if checkpoint signing material may be compromised.

## CLI

Local verification:

```bash
plugin-cli audit verify --log data/plugins/audit.log --checkpoint data/plugins/audit.checkpoint.json
plugin-cli audit status --log data/plugins/audit.log --checkpoint data/plugins/audit.checkpoint.json
```

Local checkpoints are useful for tests and deployment smoke checks. They are not a substitute for an external append-only anchor.
