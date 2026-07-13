# Stack Migration Runbook

## Verify

```bash
npm ci
PHOENIX_ENV=local npm run verify
```

## Run with optional database

```bash
PHOENIX_ENV=local npm run dev
```

## Run full local stack

```bash
docker compose up --build
```

## Rollback

Re-deploy the verified 3.0.0 Slice 0 artifact. No persistent domain migrations exist in this release.
