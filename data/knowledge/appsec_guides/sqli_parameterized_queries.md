# SQL Injection Remediation: Parameterization First

**Source type:** AppSec remediation playbook  
**Related:** OWASP A03:2021 Injection; CWE-89  
**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

## Scanner finding interpretation

When a scanner shows `account_id` (or similar) concatenated into SQL and a boolean payload like `' OR '1'='1` returns extra rows, treat it as confirmed **SQL injection** with high confidence — especially on financial transaction search endpoints.

## Prefer these controls (in order)

1. **Parameterized queries / prepared statements** — bind `account_id` as data, never as SQL text.
2. **Safe ORM APIs** that parameterize under the hood (avoid raw string SQL).
3. **Allowlist** validation for expected formats (UUID, numeric ID) as defense-in-depth — not a substitute for parameterization.
4. Least-privilege DB accounts; no DDL from app role.
5. Consider query allowlisting / stored procedures only with care (still parameterize).

## Avoid as primary “fixes”

- Manual escaping alone (error-prone, dialect-specific).
- Blacklists of characters (`'`, `--`) — attackers bypass them.
- “We use an ORM” without auditing raw queries / `order_by` injection patterns.

## Example pattern (conceptual)

```text
// Vulnerable
query = "SELECT * FROM tx WHERE account_id = '" + account_id + "'"

// Fixed
query = "SELECT * FROM tx WHERE account_id = ?"
execute(query, [account_id])
```

## AppSec answer guidance

Remediation answers should bind to **endpoint + parameter** from the finding (e.g., `GET /api/v1/transactions/search`, `account_id`) and lead with parameterization/ORM, then validation and DB privileges.
