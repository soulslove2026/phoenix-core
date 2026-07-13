# Identity Slice 1 — Verified Historical Baseline

Identity Slice 1 and its constitutional hardening were verified through v3.3.3.

## Delivered baseline

- account registration and login;
- normalized email uniqueness;
- password hashing;
- opaque server-side sessions;
- PostgreSQL constraints and migration history;
- unit and integration tests;
- OpenAPI contracts;
- exact repository manifests and checksum gates.

## Superseded controls

Identity Slice 2 v3.4.0 replaces the per-process throttling and unverified registration model with distributed abuse protection, verified-email gating, password recovery, keyed token hashing, encrypted notification outbox records, hardened session lifetime, rotation, inventory, and security events.

This file is historical context and is not the current release authority.
