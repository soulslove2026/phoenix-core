# Phoenix Core

**Version:** `4.0.0`
**Milestone:** Multi-Tenant Platform Foundation Release 1
**Status:** Candidate
**Production ready:** No

Phoenix Core is the Node.js 24, TypeScript, Fastify, and PostgreSQL implementation of the Phoenix modular monolith.

## Verified foundation

Identity Slice 2 Phase B and the Phase C internal workflows are verified. Local Windows Hello Passkey registration and authentication passed as truthful local engineering evidence, but remain non-qualifying for staging or production closure.

## Staging Assurance Foundation

Version 3.8.0 adds a governed preproduction contract:

- explicit, validated staging environment identity;
- mandatory HTTPS proxy posture, database, operations monitoring, and deployment metadata;
- non-local WebAuthn RP ID and HTTPS-only origins;
- secret-file loading for deployed environments;
- provider-neutral Docker Compose staging topology;
- sanitized staging preflight and remote smoke commands;
- a dedicated GitHub staging-foundation validation workflow;
- explicit separation between infrastructure readiness and real-world assurance evidence.

## CI reconciliation R2

The release snapshot includes a security-preserving CI reconciliation for governed environment-file tracking, canonical LF checkout, disabled Passkey harness behavior in CI integration tests, and complete non-secret Compose interpolation. See `docs/STAGING_FOUNDATION_CI_RECONCILIATION.md`.

## Commands

```bash
npm ci
npm run check
npm test
npm run test:integration
npm run build
npm run staging:preflight
npm run staging:smoke
npm run assurance:evidence:validate -- <external-evidence-directory>
```

## Security boundary

The staging Passkey harness is disabled by default and may be enabled only during an approved ceremony. It is forbidden outside local, local-compose, and staging. Staging secrets, database, provider credentials, and test data must be independent from every other environment. A green staging workflow proves the deployment contract, not a completed Passkey ceremony or production readiness.

## Next gate

Deploy the verified immutable image behind a real HTTPS staging domain, run preflight and smoke validation, complete real-device Passkey registration and authentication, sanitize the evidence, and validate it as `environment: staging`.

## Assurance Operator 3.9.0

Version 3.9.0 adds a one-command governed operator that validates sanitized external evidence, creates a deterministically ordered assessment report outside the repository, and can fail closed when complete qualifying evidence is required. See `docs/ASSURANCE_OPERATOR.md`.


## Platform Foundation 4.0.0

Version 4.0.0 introduces governed organizations, memberships, authenticated tenant context, repository-enforced isolation, idempotent organization creation, and platform audit events. See `docs/PLATFORM_FOUNDATION.md`.
