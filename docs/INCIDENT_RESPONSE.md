# Identity Incident Response

`npm run incident:snapshot` creates a privacy-preserving aggregate report covering security-event types and outcomes, session counts, and notification queue health. It excludes direct identifiers, hashes, tokens, addresses, authenticator data, and encrypted payloads.

The operator must preserve immutable logs, record the investigation timeline, rotate affected secrets, revoke sessions where required, notify responsible stakeholders, and follow legal notification duties. The snapshot is supporting evidence, not a replacement for centralized logs or a formal incident-management platform.
