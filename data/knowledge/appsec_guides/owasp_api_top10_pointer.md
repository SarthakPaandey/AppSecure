# OWASP API Security Top 10 (complement to OWASP Top 10 2021)

**Source type:** Standard pointer for API-centric scans  
**Official:** https://owasp.org/API-Security/

Modern API / fintech targets (like a wealth platform API) often map more cleanly to the **API Security Top 10** than only the generic web Top 10.

## High-value mappings for this style of scan

| API Top 10 theme | Typical scan titles in this dataset |
|------------------|-------------------------------------|
| API1 Broken Object Level Authorization | IDOR on accounts / document download |
| API2 Broken Authentication | JWT none, weak login controls |
| API3 Broken Object Property Level Authorization | Mass assignment (`role` on profile) |
| API7 Server Side Request Forgery | Document import `source_url` |
| API8 Security Misconfiguration | Missing headers, GraphQL introspection |

## How to use in answers

- Prefer **API1** language when discussing BOLA/IDOR on REST resources.
- Still cite the finding’s stored `owasp_category` (A01/A07/…) as primary, and mention API Top 10 as **additional framing** for API products.
- Do not invent API Top 10 mappings for findings that do not fit.

## Note

This guide complements (does not replace) OWASP Top 10 2021 documents bundled in this knowledge base.
