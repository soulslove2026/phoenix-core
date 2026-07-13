# Identity Slice 1

## Scope

This slice introduces:

- account registration;
- email normalization and uniqueness;
- password hashing using Node.js scrypt;
- login;
- opaque session tokens stored only as SHA-256 hashes;
- authenticated current-user lookup;
- logout and revocation;
- PostgreSQL migrations;
- unit and integration tests;
- API contracts and OpenAPI generation.

## Explicitly Deferred

- email verification;
- password reset;
- MFA/passkeys;
- social login;
- device management;
- rate-limit infrastructure;
- session rotation;
- account recovery;
- administrator identity;
- regional identity providers.

## Security Boundary

This release is Candidate until GitHub Actions passes with PostgreSQL migration, tests, build, and Docker verification.
