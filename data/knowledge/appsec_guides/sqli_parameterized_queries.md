# SQL Injection Remediation: Parameterization First

**Source type:** AppSec remediation playbook  
**Related:** OWASP A03:2021 Injection; CWE-89  
**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

## Pattern

User-controlled input is concatenated into SQL. Scanners often confirm with boolean/time payloads or multi-row responses on search/filter endpoints.

## Prefer these controls (in order)

1. **Parameterized queries / prepared statements** — bind inputs as data, never as SQL text.
2. **Safe ORM APIs** that parameterize under the hood (audit raw SQL / dynamic `ORDER BY`).
3. **Allowlist** validation for expected formats (UUID, numeric ID) as defense-in-depth — not a substitute for parameterization.
4. Least-privilege DB accounts; no DDL from the app role.
5. Query allowlisting / stored procedures only with care (still parameterize).

## Avoid as primary “fixes”

- Manual escaping alone (error-prone, dialect-specific).
- Blacklists of characters (`'`, `--`) — attackers bypass them.
- “We use an ORM” without auditing raw queries and dynamic sort/filter paths.

## Example pattern (conceptual)

```text
// Vulnerable
query = "SELECT * FROM table WHERE col = '" + user_input + "'"

// Fixed
query = "SELECT * FROM table WHERE col = ?"
execute(query, [user_input])
```

## AppSec answer guidance

Bind remediation to the finding’s **endpoint + parameter** from the store. Lead with parameterization/ORM, then validation and DB privileges.
