# Breached-password Screening

Registration and password reset use the HIBP Pwned Passwords range API. Phoenix sends only the first five hexadecimal characters of the SHA-1 password digest, requests response padding, sets an explicit user agent, and never sends the password or complete digest.

Production defaults to `required`, which fails closed when the screening service is unavailable. CI disables the external call and validates the client behavior through deterministic tests.
