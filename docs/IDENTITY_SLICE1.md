# Identity Slice 1 — Reconciled and Hardened

## Delivered

- account registration and login;
- strict normalized Internet email validation;
- password hashing with Node.js `scrypt`;
- opaque session issuance, lookup, expiry, and revocation;
- PostgreSQL uniqueness and integrity constraints;
- race-safe duplicate registration handling;
- configurable bounded session lifetime;
- bounded per-process registration/login throttling;
- ordered, checksummed, transactional migration history;
- `updated_at` database trigger;
- unit and PostgreSQL integration tests;
- JSON Schema and OpenAPI contracts;
- repository consistency and checksum gates.

## Deferred to Identity Slice 2

- email ownership verification;
- password reset and account recovery;
- MFA and passkeys;
- breached-password screening;
- distributed rate limiting;
- device and session inventory;
- session rotation and global logout;
- risk-based authentication and anomaly detection.

## Release state

Identity Slice 1 v3.3.1 was verified. The v3.3.2 reconciliation and hardening release is Candidate until GitHub Actions passes on Node.js 24 with PostgreSQL 18 and Docker build verification.
