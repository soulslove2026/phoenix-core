# Artifact Attestations

The production-assurance workflow creates a release archive outside the repository workspace, generates a CycloneDX SBOM, records SHA-256 checksums, and uses `actions/attest@v4` for provenance and SBOM attestations.

Attestations establish where and how an artifact was built. They do not prove that the application is vulnerability-free or operationally safe. Consumers must verify attestations, digests, release identity, environment policy, and deployment approvals.
