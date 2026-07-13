# Phoenix Core Security Policy

## Implemented controls

- Passwords are stored only as `scrypt` hashes with per-password random salts.
- Session tokens contain 256 bits of randomness; only SHA-256 token hashes are stored.
- Sessions expire and can be revoked.
- Email addresses are normalized and structurally validated before persistence.
- PostgreSQL enforces normalized email uniqueness and identity constraints.
- Duplicate registration races are mapped to controlled conflict responses.
- Login errors do not distinguish unknown users from incorrect passwords.
- Registration and login use bounded per-process throttling with a capped in-memory key set and structured rate-limit events.
- Request bodies, request identifiers, security headers, and error responses are bounded.
- Database migrations are ordered, checksummed, transactional, and protected by an advisory lock.
- Containers run as a non-root user.

## Production blockers

This release is not production-ready. Email verification, account recovery, MFA/passkeys, breached-password screening, distributed throttling, device/session inventory, anomaly detection, global logout, transport/secret deployment controls, and security alerting remain required.

## Reporting

Do not commit secrets or production data. Report suspected vulnerabilities privately to the repository owner with reproduction steps and impact. Do not disclose a vulnerability publicly before remediation coordination.
