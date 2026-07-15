# Staging secret files

Create these files outside the repository with owner-only permissions:

- `postgres_password`
- `database_url`
- `identity_token_pepper`
- `identity_notification_key`
- `identity_privacy_key`
- `identity_mfa_key`
- `operations_token`
- `notification_provider_token` only when the notification profile is enabled

Every identity and operations secret must be independently generated. Do not reuse local, CI, staging, recovery, or production values. The application accepts direct environment values for local compatibility, but governed deployment should use the corresponding `_FILE` variables.
