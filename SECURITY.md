# Phoenix Core Security Policy

## Current Identity Controls

- email verification before session issuance;
- generic registration and password recovery requests;
- single-use, expiring verification and recovery tokens;
- HMAC-SHA-256 token hashes with a deployment secret;
- AES-256-GCM encrypted notification outbox payloads;
- scrypt password hashing using N=131072, r=8, p=1;
- 15-character minimum password policy without composition rules;
- absolute and idle session expiration;
- session rotation, listing, targeted revocation, and logout-all;
- auth-version invalidation after password recovery;
- distributed PostgreSQL rate limiting;
- pseudonymized IP and user-agent security signals;
- append-only security event records;
- strict API security headers and configurable TLS enforcement;
- repository integrity, dependency audit, CodeQL, and Dependabot gates.

## Mandatory Remaining Controls

Email delivery must use a production worker with least-privilege key access. Passkeys/WebAuthn, MFA and recovery codes, breached-password screening, advanced abuse detection, production alerting, key rotation, external penetration testing, and incident response exercises are mandatory before production readiness.

Never submit credentials, tokens, notification keys, token peppers, private keys, or production data in an issue.

Pre-v3.4 sessions are revoked during migration because token hashing changes to keyed HMAC. Existing pre-verification accounts must complete email verification before new session issuance.

CI generates a CycloneDX SBOM, performs production and full dependency audits, runs CodeQL, and reviews pull-request dependency changes.
