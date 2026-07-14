# Backup and Restore Drill

The `Production Assurance Evidence` workflow uses PostgreSQL 18 tooling to:

- create a custom-format dump;
- calculate its SHA-256 digest;
- restore it into a separate database;
- verify the migration ledger, required tables, and referential integrity;
- delete the test dump before artifact upload.

Only the digest is retained. Production exercises must additionally test encrypted backup storage, access controls, retention, point-in-time recovery, recovery time, recovery point objectives, and restoration into an isolated environment.
