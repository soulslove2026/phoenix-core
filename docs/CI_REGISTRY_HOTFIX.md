# CI Registry Hotfix — v3.2.1

## Root Cause

The generated `package-lock.json` contained resolved package URLs pointing to a private build-environment registry. GitHub-hosted runners cannot access that registry, causing `npm ci` to wait until network timeouts.

## Correction

- Replaced 126 private registry references with `https://registry.npmjs.org/`.
- Added a CI check that fails immediately if private registry references return.
- Pinned the workflow registry to the public npm registry.
- Added installation timeout, bounded retries, and verbose diagnostics.
- Disabled audit, funding output, and progress during CI installation.

## Scope

This hotfix changes dependency retrieval and CI diagnostics only. It does not introduce product or identity logic.
