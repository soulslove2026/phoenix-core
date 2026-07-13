# Slice 0 Runbook

Start: `PHOENIX_ENV=local npm start`

Verify: `curl -i http://127.0.0.1:3000/health` and `/ready`.

Test: `npm run check && npm test`.

Rollback: Slice 0 has no persistent state; replace it with the previous verified image or commit.
