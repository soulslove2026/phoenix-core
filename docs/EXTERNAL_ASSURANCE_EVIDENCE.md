# External Assurance Evidence Kit

The kit records eight mandatory Phase C evidence classes without storing direct identifiers or credentials.

Real evidence must remain outside the repository in approved encrypted storage. The CLI validates sanitized JSON, rejects common secret and identity fields, requires redacted artifact hashes, and creates a deterministic SHA-256 manifest only when every gate has passed exactly once.

A green `External Assurance Control Validation` workflow validates the tooling and blocked templates only. It is not proof that external assurance has completed.
