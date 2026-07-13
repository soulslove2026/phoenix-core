# Identity Security Operations Runbook

## Install and verify

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run check
npm test
npm run build
npm audit --audit-level=high
```

## Generate local secrets

Generate three independent values of at least 32 random bytes, encoded with base64url, for:

- `PHOENIX_IDENTITY_TOKEN_PEPPER`
- `PHOENIX_IDENTITY_NOTIFICATION_KEY`
- `PHOENIX_IDENTITY_PRIVACY_KEY`

Never reuse production values in local, CI, staging, or test environments.

## Apply migrations

```bash
PHOENIX_ENV=local \
PHOENIX_DATABASE_REQUIRED=true \
PHOENIX_DATABASE_URL=postgres://phoenix:phoenix@localhost:5432/phoenix \
PHOENIX_IDENTITY_TOKEN_PEPPER=<secret> \
PHOENIX_IDENTITY_NOTIFICATION_KEY=<secret> \
PHOENIX_IDENTITY_PRIVACY_KEY=<secret> \
npm run migrate
```

The runner records SHA-256 checksums, rejects modified applied migrations, uses transactions, and takes a PostgreSQL advisory lock. Running it repeatedly is safe.

## Full local stack

Set the three secrets in the shell, then run:

```bash
docker compose up --build
```

Compose applies compiled migrations before startup and runs the application read-only, non-root, without Linux capabilities.

## Expected failure behavior

- Missing secrets stop database-backed startup.
- HTTP is rejected when production TLS enforcement is enabled.
- Registration and recovery requests return generic acceptance responses.
- Invalid credentials return a generic `401`.
- Correct credentials for an unverified account return `403` without issuing a session.
- Abuse limits return `429` with `Retry-After`.
- Invalid, expired, consumed, or replayed action tokens are rejected.
- Password recovery revokes every session.
- Migration checksum mismatch stops deployment.

## Rollback boundary

Migration 003 changes the security model and revokes legacy session hashes. Do not roll the application back to a pre-v3.4 identity implementation without an explicitly reviewed emergency plan, because older code does not enforce the verified-email and keyed-token boundaries. Prefer roll-forward remediation. Never delete migration history or durable identity records during an application rollback.
