# Assurance Operator

Phoenix Core 3.9.0 adds a single governed operator command over the existing external-assurance evidence schema.

## Purpose

The operator reduces manual steps without weakening the evidence boundary. It:

- reads sanitized external evidence from a directory outside the repository;
- validates every record with the existing constitutional schema;
- produces one deterministically ordered machine-readable assessment report;
- produces one human-readable summary;
- returns exit code `2` when `--require-complete` is used and closure is incomplete;
- never stores real evidence inside the governed source repository.

## Commands

Build first:

```bash
npm run build
```

Create an operator report:

```bash
npm run assurance:operator -- <external-evidence-directory> <new-report-directory>
```

Require complete qualifying evidence:

```bash
npm run assurance:operator -- <external-evidence-directory> <new-report-directory> --require-complete
```

Development mode:

```bash
npm run assurance:operator:dev -- <external-evidence-directory> <new-report-directory>
```

Both directories must be outside the repository. The report directory must not already exist.

## Outputs

- `operator-report.json`
- `operator-summary.txt`

The report contains only validated record metadata, assessment results, counts, and recommendations. It hashes the canonical evidence directory path instead of exposing it. Assessment ordering and recommendations are deterministic; `generatedAt` records the execution time, so complete report bytes are intentionally not reproducible.
