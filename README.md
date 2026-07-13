# Phoenix Core

**Version:** `3.3.2`  
**Release:** Identity Slice 1 Constitutional Reconciliation and Hardening — Release 1  
**Status:** Candidate pending GitHub Actions verification  
**Previous verified milestone:** Identity Slice 1 v3.3.1  
**Production-ready:** No

Phoenix Core is a modular-monolith implementation using Node.js 24 LTS, TypeScript 5.9, Fastify 5, PostgreSQL 18, JSON Schema/OpenAPI, and OCI containers.

## Identity Slice 1

Implemented endpoints:

- `POST /v1/identity/register`
- `POST /v1/identity/login`
- `GET /v1/identity/me`
- `POST /v1/identity/logout`

The hardening release adds strict email validation, race-safe duplicate-account handling, configurable session lifetime, per-process authentication throttling, migration history with checksums and advisory locking, `updated_at` enforcement, explicit unit-test discovery, and repository consistency gates.

## Local verification

```bash
npm ci
PHOENIX_ENV=local npm run check
PHOENIX_ENV=local npm test
PHOENIX_ENV=local npm run build
```

Run PostgreSQL migrations:

```bash
PHOENIX_ENV=local \
PHOENIX_DATABASE_REQUIRED=true \
PHOENIX_DATABASE_URL=postgres://phoenix:phoenix@localhost:5432/phoenix \
npm run migrate
```

Run the complete local stack:

```bash
docker compose up --build
```

Documentation is available at `/documentation`. Health and readiness endpoints are `/v1/system/health` and `/v1/system/ready`.

## Security boundary

Passwords are hashed with `scrypt`; opaque session tokens are generated from 256 bits of randomness and only SHA-256 token hashes are persisted. Invalid login responses are generic. Registration conflicts are race-safe. Authentication endpoints have a bounded per-process rate-limit baseline.

The project must not be exposed as a production identity service until email ownership verification, recovery, MFA/passkeys, breached-password screening, distributed rate limiting, device/session management, and operational alerting are implemented and verified.

## Repository integrity

`npm run check:repo` enforces version synchronization, manifest coverage, checksums, current documentation language, test discovery, and public npm registry portability.
