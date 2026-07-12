# OWASP API Security Top 10 (complement to OWASP Top 10 2021)

**Source type:** Standard pointer for API-centric scans  
**Official:** https://owasp.org/API-Security/

API and mobile backends often map more cleanly to the **API Security Top 10** than only the generic web Top 10.

## High-value theme mappings (pattern → API Top 10)

| API Top 10 theme | Typical scanner titles / patterns |
|------------------|-----------------------------------|
| API1 Broken Object Level Authorization | IDOR / BOLA on object resources |
| API2 Broken Authentication | JWT misconfiguration, weak login controls |
| API3 Broken Object Property Level Authorization | Mass assignment of privileged fields |
| API7 Server Side Request Forgery | Unvalidated server-side URL fetch |
| API8 Security Misconfiguration | Missing headers, open GraphQL introspection |

## How to use in answers

- Prefer **API1** language when discussing BOLA/IDOR on REST resources.
- Still cite the finding’s stored `owasp_category` (A01/A07/…) as primary; API Top 10 is **additional framing**.
- Do not invent API Top 10 mappings for findings that do not fit.

## Note

This guide complements (does not replace) OWASP Top 10 2021 documents in this knowledge base.
