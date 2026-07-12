# JWT Authentication: Rejecting the `none` Algorithm

**Source type:** AppSec remediation playbook  
**Related:** OWASP A07:2021; CWE-287; JWT RFC 7519 / best practices  
**Reference:** https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

## Pattern

If a verify or accept path trusts the token `alg` header and allows `"alg":"none"` (or fails to pin algorithms), attackers can forge claims without a valid signature. This is classic **authentication bypass**.

## Root cause pattern

- Library configured to trust `alg` from the token.
- No explicit allowlist (e.g. only `RS256` or `HS256`).
- Signature verification skipped when `alg=none`.

## Exploitation sketch

1. Decode a legitimate JWT; edit claims as needed (`sub`, `role`, scopes).
2. Set header to `{"alg":"none","typ":"JWT"}` (or algorithm-confusion variants).
3. Send payload with empty / omitted signature section as required by the library.
4. If the verify endpoint returns valid/authenticated, identity is forged.

## Remediation checklist

- **Allowlist** algorithms server-side; never treat client `alg` as authority.
- Explicitly **reject** `none` and symmetric/asymmetric confusion cases.
- Use maintained JWT libraries; keep them updated.
- Validate `exp`, `iss`, `aud` as applicable; short-lived access tokens.
- Prefer asymmetric keys (RS256/ES256) for distributed services; protect HS* secrets.

## AppSec answer guidance

Remediation is about **verification policy**, not “use JWT.” Tie advice to the finding’s **method/endpoint** and state: whitelist algorithms; reject `none`.
