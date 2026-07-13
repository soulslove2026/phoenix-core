# Dependency Update Runbook

1. Review advisory, upstream repository, release notes, license, and runtime.
2. Apply changes in a dedicated branch.
3. Install with `npm ci --ignore-scripts`.
4. Run production and full dependency audits.
5. Generate and inspect the CycloneDX SBOM.
6. Run repository, security, TypeScript, unit, integration, build, and Docker gates.
7. Regenerate manifest and SHA-256 checksums.
8. Synchronize documentation and traceability.
9. Require green CI, CodeQL, Dependency Review, and documentation workflows.
