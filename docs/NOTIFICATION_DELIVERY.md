# Notification Delivery

Identity notification payloads are AES-256-GCM encrypted before insertion into the transactional outbox. A separate worker claims records with `FOR UPDATE SKIP LOCKED`, uses provider idempotency keys, enforces HTTPS, disables redirects, applies request timeouts, retries with bounded backoff, and dead-letters exhausted messages.

The worker requires a real provider endpoint, bearer credential, and verified sender address. Provider delivery metrics and alerting remain deployment requirements.
