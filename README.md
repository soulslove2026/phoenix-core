# Phoenix Core

**Version:** `3.6.0`  
**Milestone:** Identity Slice 2 Phase C — Production Assurance Foundation Release 1  
**Status:** Candidate  
**Production ready:** No

Phoenix Core is the Node.js 24, TypeScript, Fastify, and PostgreSQL implementation of the Phoenix modular monolith.

## Verified foundation

Identity Slice 2 Phase B is Verified and includes email verification, password recovery, hardened sessions, Passkeys, TOTP MFA, one-time recovery codes, breached-password screening, distributed throttling, immutable security events, and an encrypted notification-delivery worker.

## Phase C Release 1

- same-origin browser Passkey validation harness for controlled environments;
- protected aggregate operations monitoring and Prometheus metrics;
- transactional notification/MFA key rotation with dry-run and explicit apply controls;
- notification-provider smoke-test command;
- privacy-preserving incident snapshots;
- PostgreSQL backup/restore drill and integrity verification;
- release provenance and SBOM artifact attestations;
- continued exact manifests, checksums, audits, CodeQL, and clean-workspace enforcement.

## Commands

```bash
npm ci
npm run check
npm test
npm run test:integration
npm run build
npm run migrate
npm run notifications:worker
npm run notifications:smoke
npm run identity:keys:rotate
npm run incident:snapshot
```

## Security boundary

The browser harness is forbidden in production. Operations endpoints require a dedicated secret and private-network protection. Key rotation requires an approved maintenance window. Real-browser/device evidence, real provider delivery, production secret management, alerts, deployment recovery evidence, privacy/legal review, and independent penetration testing remain mandatory.
