# Phoenix Core

**Version:** `3.4.2`  
**Milestone:** Identity Slice 2 — Release 1  
**Status:** Candidate  
**Production ready:** No

Identity Slice 2 adds email ownership verification, password recovery, keyed opaque-token storage, encrypted notification outbox payloads, absolute and idle session expiry, session rotation and management, distributed PostgreSQL rate limiting, security audit events, stronger password hashing, TLS enforcement controls, CodeQL, dependency automation, and additional CI security gates.

## Identity API

- `POST /v1/identity/register`
- `POST /v1/identity/email-verification/request`
- `POST /v1/identity/email-verification/confirm`
- `POST /v1/identity/login`
- `POST /v1/identity/password-reset/request`
- `POST /v1/identity/password-reset/confirm`
- `GET /v1/identity/me`
- `POST /v1/identity/sessions/rotate`
- `GET /v1/identity/sessions`
- `DELETE /v1/identity/sessions/:sessionId`
- `POST /v1/identity/logout`
- `POST /v1/identity/logout-all`

Registration and recovery request responses are deliberately generic. Raw verification and recovery tokens are never stored; notification payloads are encrypted with AES-256-GCM before entering the outbox.

## Security Boundaries

This release does not claim public production readiness. Passkeys/WebAuthn, TOTP MFA, recovery codes, breached-password provider integration, a production notification worker, privileged administrator authentication, risk scoring, and external penetration testing remain required gates.

## Clean Snapshot Installation

Preserve `.git`, remove all other files in the local repository, and copy this complete snapshot. This prevents exact-manifest drift.

CI generates a CycloneDX SBOM, performs production and full dependency audits, runs CodeQL, and reviews pull-request dependency changes.

## Dependency Governance

Routine automatic version-update pull requests are disabled. Dependabot security alerts and security updates remain enabled. Planned upgrades are delivered through reviewed maintenance releases with synchronized manifests, checksums, audits, SBOM evidence, tests, CodeQL, and documentation.

## CI Evidence Isolation

CycloneDX SBOMs and other generated security evidence are written to the GitHub runner temporary directory, not the governed repository workspace. CI checks repository authority before generation and confirms that the working tree remains clean afterward.
