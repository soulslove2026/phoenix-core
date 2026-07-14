# Identity Encryption-Key Rotation Runbook

The key-rotation script re-encrypts notification payloads, TOTP enrollments, TOTP factors, and WebAuthn challenges inside one PostgreSQL transaction protected by an advisory lock.

1. Back up the database and verify restoration.
2. Generate independent new notification and MFA keys. Each new key must differ from the effective current key, and the two new keys must differ from one another.
3. Run a dry run with `PHOENIX_KEY_ROTATION_APPLY=false`.
4. Review row counts and errors.
5. Schedule a maintenance window that prevents concurrent encrypted writes.
6. Set `PHOENIX_KEY_ROTATION_APPLY=true` and `PHOENIX_KEY_ROTATION_CONFIRM=ROTATE_IDENTITY_KEYS`.
7. Run `npm run identity:keys:rotate`.
8. Atomically deploy the new runtime secrets and restart all API and worker instances.
9. Test login, TOTP, Passkeys, verification, reset, and notifications.
10. Revoke and destroy old keys according to policy.

The script never logs plaintext or cryptographic key material. This maintenance-window method does not claim zero-downtime rotation.

## Scope boundary

This tool rotates AES-GCM encryption keys for encrypted notification and MFA payloads. It does not rotate the token pepper or privacy-HMAC key. Rotating those values requires a separate invalidation or dual-read migration plan because existing token and privacy hashes cannot be reversed and re-keyed in place.
