# JWT Authentication: Rejecting the `none` Algorithm

**Source type:** AppSec remediation playbook  
**Related:** OWASP A07:2021; CWE-287; JWT RFC 7519 / best practices  
**Reference:** https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

## Why scanners flag this

If a verify endpoint accepts tokens with `"alg":"none"` (or fails to pin allowed algorithms), attackers can forge a token payload (e.g., `role=admin`) without a signature. This is a classic **authentication bypass**, often CRITICAL on auth services.

## Root cause pattern

- Library configured to trust the `alg` header from the token.
- No explicit allowlist of algorithms (e.g., only `RS256` or `HS256`).
- Signature verification skipped when `alg=none`.

## Exploitation sketch

1. Decode a legitimate JWT; keep or edit claims (`sub`, `role`).
2. Set header to `{"alg":"none","typ":"JWT"}`.
3. Send payload with empty signature section as required by the library.
4. If `/auth/verify` returns `valid: true`, authentication is bypassed.

## Remediation checklist

- **Allowlist** algorithms server-side; never take `alg` from untrusted input as authority.
- Explicitly **reject** `none` and symmetric/asymmetric confusion cases.
- Use well-maintained JWT libraries; keep them updated.
- Short-lived access tokens; validate `exp`, `iss`, `aud` as applicable.
- Prefer asymmetric keys (RS256/ES256) for distributed services; protect secrets for HS*.

## AppSec answer guidance

Remediation answers should not say “use JWT” generically — the finding is about **verification policy**. Tie advice to the scan endpoint (e.g., `POST /api/v1/auth/verify`) and “whitelist algorithms; reject none.”
