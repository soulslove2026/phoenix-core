# Release 2 — Clean Snapshot Correction

Release 1 failed because overlay copying preserved files outside the authoritative manifest.

Release 2 is a complete clean snapshot. Preserve `.git`, remove every other local repository file, and then copy this snapshot.

Obsolete Slice 0 paths that must not remain:

- `scripts/check.mjs`
- `src/config.mjs`
- `src/logger.mjs`
- `src/server.mjs`
- `test/config.test.mjs`
- `test/server.test.mjs`

The checker now prints exact unmanaged and missing paths.
