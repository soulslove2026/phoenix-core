# Phoenix Core

**Version:** `3.5.0`  
**Milestone:** Identity Slice 2 — Phase B, Release 1  
**Status:** Candidate  
**Production ready:** No

Phase B adds phishing-resistant Passkeys/WebAuthn, TOTP multifactor authentication, one-time recovery codes, breached-password screening, recent-authentication gates, stronger session assurance, and an encrypted transactional notification-delivery worker.

## Identity API additions

- `POST /v1/identity/mfa/complete`
- `GET /v1/identity/mfa/status`
- `POST /v1/identity/mfa/totp/enrollment/start`
- `POST /v1/identity/mfa/totp/enrollment/confirm`
- `POST /v1/identity/mfa/recovery-codes/regenerate`
- `POST /v1/identity/mfa/totp/disable`
- `POST /v1/identity/passkeys/registration/options`
- `POST /v1/identity/passkeys/registration/verify`
- `POST /v1/identity/passkeys/authentication/options`
- `POST /v1/identity/passkeys/authentication/verify`
- `GET /v1/identity/passkeys`
- `DELETE /v1/identity/passkeys/:passkeyId`

## Security posture

- Passkeys require discoverable credentials and user verification.
- TOTP secrets are encrypted; accepted time steps cannot be replayed.
- Recovery codes are one-time and stored only as keyed hashes.
- Passwords are screened with the HIBP k-anonymity range API in production-required mode.
- Sensitive factor operations require recent authentication and AAL2 where applicable.
- Notification payloads are encrypted at rest and delivered by a retrying, idempotent worker.
- Exact manifests, checksums, audits, SBOM, CodeQL, dependency review, migrations, tests, build, and Docker remain mandatory gates.

## Local verification

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run check
npm test
npm run build
npm audit --audit-level=high
```

## Clean snapshot installation

Preserve `.git`, remove every other local repository item, and copy this complete snapshot. The release remains Candidate until GitHub Node.js 24, PostgreSQL 18, Docker, CodeQL, and documentation evidence pass.
