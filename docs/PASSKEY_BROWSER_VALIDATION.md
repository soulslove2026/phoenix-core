# Passkey Browser Validation

Set `PHOENIX_PASSKEY_VALIDATION_ENABLED=true` only in a controlled validation environment. The application serves `/passkey-validation/` on the same origin as the API.

The harness:

- checks WebAuthn and platform-authenticator capabilities;
- performs registration and username-less authentication;
- keeps session tokens in memory only;
- exports sanitized evidence without raw credential responses or session tokens;
- uses restrictive CSP, no-store caching, and noindex headers.

The configuration loader refuses to enable the harness when `PHOENIX_ENV=production`.

Evidence must cover current Chrome, Edge, Firefox, Safari, Android, iOS, Windows Hello, Apple platform passkeys, and at least one external security key where supported. Browser-specific behavior must be recorded rather than hidden.
