# Phase C Compiled Operational Tool Ordering Hotfix

## Confirmed failure

Core commit `c590f6e` passed CodeQL and Production Assurance Evidence but failed CI at `Validate incident-safe snapshot`.

`MODULE_NOT_FOUND: dist/scripts/security-incident-snapshot.js`

## Root cause

`incident:snapshot` intentionally runs the compiled artifact:

`node dist/scripts/security-incident-snapshot.js`

CI called it before `npm run build`, so `dist/` did not exist.

## Correction

CI now builds first, verifies the compiled file exists, executes it, validates the evidence schema, and then builds the container.

## Regression prevention

Dependency governance validates the ordering in both CI and Production Assurance.

## Security boundary

The compiled production path remains mandatory. The hotfix does not replace it with a development-only loader.
