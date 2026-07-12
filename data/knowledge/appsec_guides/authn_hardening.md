# Authentication Hardening for API Login / Registration

**Source type:** AppSec remediation playbook  
**Related:** OWASP A07:2021; CWE-307, CWE-521, CWE-798  
**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

## Common scanner cluster (treat as a theme)

Scans often surface multiple related auth issues:

| Pattern | Typical finding | Priority driver |
|---------|-----------------|-----------------|
| Unlimited login attempts | Missing rate limiting | Credential stuffing / brute force |
| Short passwords accepted | Weak password policy | Account takeover at scale |
| Secrets in frontend bundles | Hardcoded API keys | Full key compromise; rotate immediately |
| Broken token verify | JWT `none` / weak validation | Complete auth bypass |

These are different CWEs but the **product risk** is the same class: attackers gain or forge identity.

## Remediation themes

### Rate limiting & abuse resistance
- Per-account and per-IP limits on `/login`; progressive delays; CAPTCHA/lockout policy as UX allows.
- Monitor anomalous auth traffic; alert on stuffing patterns.

### Password policy
- Prefer length (e.g., 12+) and breached-password checks over complex composition rules alone.
- Support password managers (long passphrases, special characters).

### Secrets management
- Never ship live third-party keys in JS bundles (`sk_live_...`).
- Server-side proxy for payments; secrets in a vault; rotate any exposed key.
- SCA/secret scanning in CI for bundles and repos.

## AppSec answer guidance

For “what authentication issues were found?”, group by theme and severity, cite concrete finding IDs, and avoid mixing in unrelated injection findings unless asked.
