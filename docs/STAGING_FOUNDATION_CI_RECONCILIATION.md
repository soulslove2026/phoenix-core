# Staging Foundation CI Reconciliation

**Release:** Phoenix Core 3.8.0 — Staging Assurance Foundation R2  
**Status:** Candidate  
**Production ready:** No

## Purpose

This reconciliation closes defects discovered by the first GitHub workflow executions without weakening the staging security contract.

## Findings and corrections

1. `deploy/staging/.env.staging.example` was governed but ignored by the broad `.env.*` rule. The file is now explicitly tracked.
2. Cross-platform line-ending conversion made repository byte checks unstable. `.gitattributes` now mandates canonical LF checkout, and checksum parsing accepts LF or CRLF defensively.
3. The integration suite enabled the browser-only Passkey validation harness in the `test` environment, which correctly violated the environment allowlist. The suite now leaves the harness disabled and explicitly verifies that its route returns `404`, while continuing to exercise the Passkey API routes.
4. Docker Compose interpolates required notification-worker values even when the profile is not launched. The staging workflow now supplies sanitized non-secret provider URL and sender values during model validation.

## Security decision

The Passkey harness allowlist remains unchanged: `local`, `local-compose`, and `staging` only. CI does not gain an exception. The correction changes the test expectation rather than weakening runtime policy.

## Verification gates

The reconciled snapshot must pass:

- repository constitutional consistency;
- security and dependency governance;
- unit tests;
- PostgreSQL integration tests;
- production build;
- provider-neutral staging Compose validation;
- CI, CodeQL, Production Assurance Evidence, External Assurance Control Validation, and Staging Foundation Validation.

A green workflow set verifies the foundation only. It does not claim a deployed HTTPS staging environment, completed staging Passkey ceremony, external assurance closure, or production readiness.
