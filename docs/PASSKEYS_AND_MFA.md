# Passkeys and MFA

Passkeys use discoverable credentials, required user verification, origin/RP-ID validation, credential counters, backup state, and one-time encrypted challenges. TOTP uses six digits, a thirty-second period, a one-step clock window, encrypted seeds, and monotonic accepted-step enforcement.

Recovery codes are generated once, shown once, normalized before verification, HMAC-hashed at rest, and consumed atomically. Recovery-code sessions cannot change authenticators.
