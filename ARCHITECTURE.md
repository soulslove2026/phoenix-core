# Phoenix Core Architecture

Phoenix Core remains a bounded-context modular monolith using Node.js 24, TypeScript 5.9, Fastify 5, PostgreSQL 18, JSON Schema/OpenAPI, OCI containers, and GitHub Actions.

## Identity Phase B boundaries

- `IdentityService` owns orchestration and security invariants.
- `PostgresIdentityRepository` owns users, actions, sessions, and audit events.
- `PostgresPhaseBIdentityRepository` owns Passkeys, TOTP, recovery codes, MFA transactions, session assurance, WebAuthn challenges, and notification delivery state.
- `PasskeyManager` isolates WebAuthn protocol verification.
- `HibpPasswordBreachChecker` isolates compromised-password screening.
- `NotificationDeliveryService` claims outbox rows transactionally and delivers them through a least-privilege provider adapter.

PostgreSQL remains authoritative truth. Passkey public keys are stored; private keys never leave authenticators. TOTP secrets and WebAuthn challenges are AES-256-GCM encrypted. Bearer and recovery tokens are persisted only as HMAC hashes.

## Assurance model

- AAL1: verified email or password without a second factor.
- AAL2: password plus TOTP, Passkey, or controlled recovery-code login.
- Recovery-code sessions are deliberately restricted from factor management.
- Sensitive operations require recent authentication; factor removal requires strong recent authentication.

## Delivery boundary

The application writes encrypted notifications transactionally. A separate worker decrypts only claimed rows, sends idempotent provider requests, retries with bounded exponential delay, and dead-letters exhausted records.

## Phase C assurance architecture

Production assurance is implemented as isolated adapters and operator tooling around the modular monolith: same-origin validation UI, protected operations routes, database-backed aggregate observability, transactional key-rotation utilities, recovery verification, and CI provenance evidence.
