# Identity Slice 1 Runbook

## Install and verify

```bash
npm ci
PHOENIX_ENV=local npm run check
PHOENIX_ENV=local npm test
PHOENIX_ENV=local npm run build
```

## Apply migrations

```bash
PHOENIX_ENV=local \
PHOENIX_DATABASE_REQUIRED=true \
PHOENIX_DATABASE_URL=postgres://phoenix:phoenix@localhost:5432/phoenix \
npm run migrate
```

The migration runner records SHA-256 checksums in `phoenix_schema_migrations`, rejects modified applied migrations, uses transactions, and takes a PostgreSQL advisory lock. Running it repeatedly is safe.

## Full local stack

```bash
docker compose up --build
```

Compose applies compiled migrations before starting the application.

## Failure behavior

- Missing required configuration stops startup.
- Required database unavailability stops startup.
- Invalid credentials return a generic `401`.
- Duplicate registration returns a controlled `409`.
- Authentication throttling returns `429` with `Retry-After`.
- Migration checksum mismatch stops deployment.

## Rollback

Application code may be rolled back to verified v3.3.1 because the v3.3.2 schema additions are backward-compatible. Do not delete migration history, identity rows, sessions, or constraints during an application rollback. Investigate and roll forward unless a separately reviewed destructive migration plan exists.
