# Phoenix Core Architecture

Phoenix Core is a bounded-context modular monolith. Identity owns user credentials, account status, and sessions behind explicit application, HTTP, and PostgreSQL repository boundaries.

## Runtime

- Node.js 24 LTS
- TypeScript 5.9 strict mode
- Fastify 5
- PostgreSQL 18
- JSON Schema and OpenAPI
- OCI containers and GitHub Actions

## Identity boundaries

HTTP routes delegate to `IdentityService`; persistence is isolated by `IdentityRepository`; PostgreSQL is authoritative truth. Plaintext passwords and session tokens never enter persistent storage.

## Evolution

Rate limiting is intentionally implemented as a replaceable per-process baseline. A distributed implementation may replace it when horizontal-scale evidence exists. Email verification, recovery, MFA/passkeys, and device/session management belong to Identity Slice 2 and must preserve the same boundaries.
