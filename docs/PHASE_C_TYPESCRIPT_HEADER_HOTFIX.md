# Phase C TypeScript Header Narrowing Hotfix

## Confirmed failure

Core commit `7989ab9` failed the `CI` workflow at `Strict TypeScript checks`:

`test/passkey-harness.test.ts(12,16): TS2345`

The `Production Assurance Evidence` workflow invokes the same strict typecheck through `npm run check`, so it was blocked by the same source defect.

## Root cause

Fastify Inject exposes response headers through Node.js `OutgoingHttpHeader`, whose type can be:

- `string`;
- `number`;
- `string[]`;
- `undefined`.

`assert.match` accepts only a string.

## Security-preserving correction

The test now:

1. reads `x-robots-tag`;
2. requires the runtime value to be a string;
3. checks that it contains `noindex`.

An unexpected number, array, or missing header fails the test. The correction is stronger than coercing the value with `String(...)`.

## Boundary

No production route, authentication control, cryptographic operation, database migration, or assurance workflow was bypassed or weakened.
