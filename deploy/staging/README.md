# Phoenix governed staging deployment

This directory defines a provider-neutral staging runtime behind an external HTTPS reverse proxy or managed load balancer.

## Security boundary

- The application port binds only to host loopback.
- PostgreSQL is reachable only on the internal data network.
- TLS terminates at a reviewed edge and forwards `X-Forwarded-Proto: https` through exactly one trusted proxy hop.
- Staging uses independent secrets and synthetic or approved data.
- The image must be immutable, preferably an OCI digest from the verified build.
- The Passkey harness is disabled by default and enabled only for an approved ceremony.

## Preflight order

1. Create secret files outside the repository with restrictive permissions.
2. Copy `.env.staging.example` to a protected operator path and replace placeholders.
3. Run the compiled `staging:preflight` command with the same effective configuration.
4. Validate the Compose model.
5. Deploy behind HTTPS.
6. Run `staging:smoke`.
7. Perform the real-browser Passkey ceremony and collect sanitized evidence.
8. Disable the Passkey harness and repeat smoke checks.

The deployment is Candidate infrastructure. It does not authorize production use or close external assurance by itself.
