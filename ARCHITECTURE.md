# Phoenix Core Architecture

Phoenix Core is a bounded-context modular monolith. Identity owns credentials, email ownership state, account status, recovery actions, sessions, abuse controls, notification-security records, and identity audit events behind explicit application, HTTP, and PostgreSQL boundaries.

## Runtime

- Node.js 24 LTS
- TypeScript 5.9 strict mode
- Fastify 5
- PostgreSQL 18
- JSON Schema and OpenAPI
- OCI containers and GitHub Actions

## Identity boundaries

HTTP routes delegate to `IdentityService`; persistence is isolated by `IdentityRepository`; PostgreSQL is authoritative transactional truth. Plaintext passwords, bearer tokens, verification tokens, and reset tokens never enter persistent storage unprotected.

The primary identity database stores HMAC token hashes. Notification delivery payloads are separately protected with AES-256-GCM. Network and user-agent signals are HMAC-pseudonymized. PostgreSQL provides distributed atomic rate-limit buckets shared across application replicas.

## Security evolution

Identity Slice 2 Release 1 implements email verification, recovery, hardened sessions, distributed abuse controls, and security events. Passkeys/WebAuthn, TOTP MFA, recovery codes, breached-password screening, risk scoring, privileged administrator isolation, and the production notification worker remain separate, mandatory gates.
