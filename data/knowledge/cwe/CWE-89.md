# CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Official URL:** https://cwe.mitre.org/data/definitions/89.html

## Description

The software constructs all or part of an SQL command using externally-influenced input without neutralizing special elements that could modify the intended SQL command.

## Mitigations

- Use parameterized queries / prepared statements exclusively for dynamic SQL.
- Use ORMs carefully; avoid raw string concatenation of user input into queries.
- Apply least privilege to the database account used by the application.
- Validate input with allowlists for expected types (e.g., UUIDs, integers).
- Escape only as a last resort and only with the correct encoding for the SQL dialect.
