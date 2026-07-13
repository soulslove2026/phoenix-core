# Identity Security Operations

## Secrets

Use independent random values for token hashing, notification encryption, and privacy pseudonymization. Store them in a managed secret service. Rotate with an overlap plan; do not rotate the token pepper without intentionally invalidating outstanding sessions and action tokens.

## Notification Outbox

The web service creates encrypted messages only. A separate worker must use least privilege, bounded retries, dead-letter handling, redacted telemetry, and short retention. Decryption keys must not be available to analytics or general support systems.

## Response

On suspected credential or token compromise: disable affected accounts where justified, increment `auth_version`, revoke sessions, invalidate action tokens, rotate relevant secrets, preserve security-event evidence, notify affected users, and document the incident.
