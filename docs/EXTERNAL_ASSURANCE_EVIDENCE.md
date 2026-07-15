# External Assurance Evidence Kit

The kit records eight mandatory Phase C evidence classes without storing direct identifiers or credentials.

Real evidence must remain outside the repository in approved encrypted storage. The CLI validates sanitized JSON, rejects common secret and identity fields, requires redacted artifact hashes, and creates a deterministic SHA-256 manifest only when every gate has passed exactly once.

A green `External Assurance Control Validation` workflow validates the tooling and blocked templates only. It is not proof that external assurance has completed.


## Provenance and closure qualification

Version 3.7.1 separates evidence validity from gate-closing eligibility. The accepted environments are `local`, `staging`, `production`, `recovery`, and `external`. Local evidence may prove an engineering exercise, but it never closes an external assurance gate. The assessment exposes `nonQualifyingKinds` so environment mismatches remain visible instead of being silently treated as passed.

See `EXTERNAL_ASSURANCE_PROVENANCE_RECONCILIATION.md` for the complete environment matrix.
