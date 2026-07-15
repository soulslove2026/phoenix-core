# External Assurance Provenance Reconciliation

Version 3.7.1 corrects a provenance ambiguity discovered during real-device Passkey validation.

A successful local Windows Hello/WebAuthn exercise is valid engineering evidence, but it is not staging or production evidence. The evidence schema therefore accepts `local` as a truthful environment while the assessment engine separately enforces environment-qualified closure rules.

## Closure qualification

| Evidence kind | Environments that may close the gate |
|---|---|
| `passkey_real_device` | `staging`, `production` |
| `notification_provider_delivery` | `staging`, `production` |
| `key_rotation_exercise` | `staging`, `production` |
| `alert_delivery` | `staging`, `production` |
| `recovery_drill` | `recovery` |
| `incident_response_exercise` | `staging`, `production`, `recovery` |
| `privacy_legal_review` | `external` |
| `penetration_test` | `external` |

A record may be structurally valid and have `status: passed` while still appearing in `nonQualifyingKinds`. Such a record proves the exercise occurred but cannot close Phase C until it is repeated in a qualifying environment.

## Local Passkey evidence

The July 2026 Windows Hello validation should be recorded as:

```json
{
  "kind": "passkey_real_device",
  "status": "passed",
  "environment": "local"
}
```

The record remains useful, approved, redacted evidence. It must not be relabeled as staging.

## Release state

Phase C remains Candidate and production readiness remains false. This reconciliation changes evidence truthfulness and assessment semantics only; it does not claim a new external gate has closed.
