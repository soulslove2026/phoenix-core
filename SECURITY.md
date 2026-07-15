# Phoenix Core Security Policy

## Phase B controls

- Passkeys/WebAuthn with required resident keys and user verification;
- TOTP MFA using RFC 6238 parameters and encrypted secrets;
- TOTP time-step replay prevention;
- ten one-time recovery codes stored only as HMAC hashes;
- recovery-code sessions blocked from factor-management operations;
- breached-password screening through the HIBP k-anonymity range protocol;
- fail-closed password screening in production-required mode;
- recent-authentication and AAL2 gates for sensitive actions;
- session assurance records and authenticator attribution;
- encrypted WebAuthn challenges and TOTP enrollment state;
- password recovery revokes all sessions through auth-version invalidation;
- encrypted transactional notification outbox and separate notification-delivery worker;
- idempotent notification provider requests, bounded retries, and dead-letter handling;
- distributed PostgreSQL abuse controls and immutable security events;
- audits, SBOM, CodeQL, dependency review, secret scanning, exact manifests, and checksums.

## Secret separation

Use independent values for token pepper, notification encryption, privacy pseudonymization, and MFA/WebAuthn encryption. Do not reuse secrets between environments. Never commit secrets, TOTP seeds, recovery codes, passkey private material, notification tokens, or production data.

## Remaining production blockers

A real notification-provider account and delivery-observability integration, managed secret rotation, edge bot defense, privileged-administrator isolation, production monitoring, tested backup restoration, external penetration testing, privacy/legal review, and operational incident exercises remain mandatory. The current release is not production-ready.

## Phase C production-assurance controls

Passkey browser validation is staging-only; operations monitoring is bearer-protected and aggregate-only; key rotation is transactional and explicitly confirmed; incident snapshots exclude direct identifiers; backup and restore are exercised; release archives and SBOMs receive artifact attestations.


## External assurance evidence

Real-world Passkey, provider, rotation, alert, recovery, incident, privacy/legal, and penetration-test evidence must be sanitized, hashed, approved, and kept outside the source repository. Tooling rejects direct identifiers and common secret-bearing fields.

## v3.8.0 governed staging controls

- Staging is a validated production-like environment identity, not an arbitrary string.
- TLS enforcement, trusted proxy configuration, deployment identity, database availability, operations monitoring, HTTPS WebAuthn origins, and non-local RP IDs are mandatory.
- Password-breach screening cannot be disabled in staging or production.
- Default local PostgreSQL credentials are rejected in staging and production.
- Deployed secrets may be mounted through absolute `_FILE` paths and are never emitted by preflight or smoke reports.
- The Passkey validation harness is disabled by default and is permitted only in local, local-compose, or staging.
- The staging application binds to loopback in the provider-neutral Compose model; PostgreSQL remains on an internal-only network.
- A valid staging deployment does not itself prove a Passkey ceremony or authorize production.
