# Identity Operations Monitoring

Enable with `PHOENIX_OPERATIONS_ENABLED=true` and a unique 32-byte base64url `PHOENIX_OPERATIONS_TOKEN`. Place the endpoints behind a private network or authenticated monitoring proxy.

Protected endpoints:

- `GET /v1/operations/identity/health`
- `GET /v1/operations/identity/metrics`

The endpoints expose aggregate counts only. They never expose emails, user identifiers, subject hashes, session tokens, authenticator material, or notification payloads.

Degraded-state thresholds are configurable for dead letters, stale delivery locks, and recent denied identity events. Alert routing and paging must be configured in the deployment platform before production readiness.
