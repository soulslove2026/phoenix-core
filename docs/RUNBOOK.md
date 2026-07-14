# Identity Phase B Security Operations Runbook

## Required independent secrets

- `PHOENIX_IDENTITY_TOKEN_PEPPER`
- `PHOENIX_IDENTITY_NOTIFICATION_KEY`
- `PHOENIX_IDENTITY_PRIVACY_KEY`
- `PHOENIX_IDENTITY_MFA_KEY`

Each value must contain at least 32 random bytes encoded as base64url and must be different per purpose and environment.

## Migrations and verification

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run check
npm run migrate
npm run migrate
npm test
npm run test:integration
npm run build
npm audit --omit=dev --audit-level=high
npm audit --audit-level=high
```

The migration ledger must contain four migrations after Phase B.

## Password screening

Production must use `PHOENIX_IDENTITY_PASSWORD_BREACH_MODE=required`. An outage returns `password_screening_unavailable`; do not silently bypass the check.

## Notification worker

Configure the HTTPS provider endpoint, bearer credential, and sender address, then run:

```bash
npm run notifications:worker
```

Alert on dead-letter growth, repeated provider failures, queue age, and delivery latency. Rotate provider credentials and encryption keys through reviewed procedures.

## Emergency boundaries

Password recovery revokes all sessions. Disabling TOTP revokes all sessions. Never manually mark MFA challenges, recovery codes, or notification rows successful without a reviewed incident procedure. Prefer roll-forward remediation; migration 004 adds durable security state.
