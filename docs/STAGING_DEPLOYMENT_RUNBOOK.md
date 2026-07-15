# Staging Deployment Runbook

## Prerequisites

- verified immutable Phoenix Core image;
- controlled HTTPS domain and edge;
- independent staging database and secrets;
- synthetic or approved data only;
- operator access and rollback authority;
- external evidence directory outside the repository.

## Procedure

1. Create independent secret files with owner-only permissions.
2. Copy `deploy/staging/.env.staging.example` to a protected operator location.
3. Replace every placeholder, including image digest, deployment identity, region, commit, RP ID, and HTTPS origin.
4. Run `npm run build` and `npm run staging:preflight` with the effective configuration.
5. Render `deploy/staging/compose.yaml` and review the result for secret leakage and public database exposure.
6. Deploy the immutable image behind exactly one trusted HTTPS proxy hop.
7. Run `npm run staging:smoke` against the public HTTPS origin.
8. Enable the Passkey harness only for an approved assurance window.
9. Complete registration and authentication on the staging origin and retain sanitized evidence.
10. Disable the harness, repeat smoke checks, and record the deployment and rollback decision.

## Stop conditions

Stop and roll back when TLS identity, deployment metadata, readiness, database availability, operations monitoring, security headers, RP/origin configuration, or secret separation cannot be proven.

## Production boundary

This runbook does not authorize production. Staging evidence closes only the specific evidence kind it proves.
