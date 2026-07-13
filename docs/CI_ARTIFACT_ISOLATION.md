# CI Artifact Isolation

## Confirmed incident

The v3.4.1 main workflow generated `phoenix-core-sbom.cdx.json` in the repository root before running the exact-manifest constitutional check. The checker correctly rejected the generated ungoverned file.

## Corrective controls

- run constitutional consistency before evidence generation;
- write SBOM evidence to `${{ runner.temp }}`;
- validate generated SBOM JSON;
- upload from temporary storage;
- fail if `git status` shows any repository change afterward.

## Rule

Build output, caches, reports, SBOMs, and other generated evidence must never alter the governed source workspace.
