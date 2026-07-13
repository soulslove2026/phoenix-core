# Repository Reconciliation — v3.3.2

This release synchronizes `package.json`, `package-lock.json`, `VERSION.json`, README, security documentation, manifests, checksums, tests, migrations, CI, and OpenAPI metadata.

## Corrected defects

- removed the stale statement that Identity was not implemented;
- made top-level unit-test discovery explicit;
- synchronized runtime and documentation versions;
- added checksum-backed migration history;
- added strict email validation and race-safe uniqueness handling;
- made session lifetime configurable and bounded;
- added an authentication throttling baseline;
- enforced `updated_at` and database constraints;
- added CI gates that detect repository drift.

## Gate

The release remains Candidate until its GitHub Actions workflow passes. Identity Slice 1 v3.3.1 remains the previous verified baseline.
