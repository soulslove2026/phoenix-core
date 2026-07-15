# Phoenix v3.8.0 — Staging Assurance Foundation

## Purpose

Establish a governed, provider-neutral staging baseline that is production-like enough to collect qualifying external-assurance evidence without claiming production readiness.

## Enforced staging contract

- `PHOENIX_ENV=staging` is an explicit environment identity.
- Database-backed operation is mandatory.
- TLS enforcement and one trusted proxy hop are mandatory.
- WebAuthn RP ID must be non-local and all origins must use HTTPS.
- Operations monitoring and a dedicated strong token are mandatory.
- Breached-password screening cannot be disabled.
- Documentation is disabled by default.
- Deployment ID, region, and immutable source commit are mandatory.
- Default local PostgreSQL credentials are rejected.
- Sensitive runtime values may be loaded from absolute `_FILE` paths.

## Evidence boundary

The preflight report proves configuration posture only. The staging smoke report proves HTTPS routing, health, readiness, database availability, security headers, and deployment identity. Neither report proves a real Passkey ceremony, provider delivery, recovery, legal approval, or penetration testing.

## Exit condition

A real-browser registration and authentication ceremony must be completed on the deployed HTTPS staging origin. The resulting sanitized evidence may then use `environment: staging` and become closure-qualified for `passkey_real_device`.
