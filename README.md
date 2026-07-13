# Phoenix Core

Production-stack migration baseline for Phoenix Core.

## Stack

- Node.js 24 LTS
- TypeScript 5.9
- Fastify 5
- PostgreSQL 18 readiness
- JSON Schema/OpenAPI

## Local verification

```bash
npm ci
PHOENIX_ENV=local npm run verify
PHOENIX_ENV=local npm run dev
```

Endpoints:

- `/v1/system/health`
- `/v1/system/ready`
- `/documentation`

This release contains no Identity domain logic. Identity Slice 1 remains gated on successful CI after migration.

## CI Registry Integrity

The committed lockfile must resolve packages only through the public npm registry. CI fails immediately if a private build-environment registry URL is detected.
