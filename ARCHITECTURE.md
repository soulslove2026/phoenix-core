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


## External assurance boundary

The source repository contains schemas, blocked templates, tests, and validation tooling only. Real assurance artifacts remain in an approved encrypted evidence store and are referenced by redacted SHA-256 metadata.

## v3.8.0 staging deployment boundary

The staging baseline is provider-neutral. Phoenix Core runs as the same immutable OCI artifact behind one reviewed HTTPS proxy hop, with PostgreSQL isolated on a private data network. Environment-specific behavior is expressed through validated runtime configuration, not code branches. Deployment identity (`deploymentId`, `region`, and source commit) is included in structured logs and health/readiness responses so evidence can be tied to the exact release candidate.

The staging preflight proves configuration posture before deployment. The remote smoke command proves HTTPS routing, security headers, readiness, database availability, optional operations health, and optional Passkey-harness exposure. Real WebAuthn registration and authentication remain a separate human-operated assurance ceremony.

## v3.9.0 assurance operator boundary

The Assurance Operator is an orchestration layer over the existing external-evidence schema. It does not create or approve real evidence. It validates sanitized records, produces deterministic assessment reports outside the repository, and preserves fail-closed completion semantics.
