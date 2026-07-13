# Identity Slice 2 — Verification, Recovery, and Session Hardening

This candidate release implements secure email verification, password recovery, encrypted notification delivery records, keyed token hashes, strong password hashing, session idle/absolute expiry, rotation, session inventory and revocation, distributed rate limiting, and auditable security events.

The notification outbox stores only AES-256-GCM ciphertext. A future least-privilege worker must claim, decrypt, deliver, mark, and purge messages. Application logs and API responses never expose verification or reset tokens.

Passkeys, TOTP MFA, recovery codes, breached-password API integration, risk scoring, and external security testing remain explicit production blockers.

Pre-v3.4 sessions are revoked during migration because token hashing changes to keyed HMAC. Existing pre-verification accounts must complete email verification before new session issuance.

CI generates a CycloneDX SBOM, performs production and full dependency audits, runs CodeQL, and reviews pull-request dependency changes.
