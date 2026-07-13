# Dependency Governance

Routine version upgrades are reviewed and released manually. Dependabot remains active for vulnerability alerts and security updates.

Approved action generations:

- `actions/checkout@v6`
- `actions/setup-node@v6`
- `actions/upload-artifact@v7`
- `github/codeql-action@v4`
- `actions/dependency-review-action@v5`

Every dependency change requires vulnerability, license, compatibility, manifest, checksum, audit, SBOM, test, build, Docker, CodeQL, and documentation evidence.

The PURLs for `actions/checkout` and `actions/dependency-review-action` are narrowly excluded from automated license detection because GitHub may report `Null` metadata. Vulnerability checks remain active.
