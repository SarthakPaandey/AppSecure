# API Security: Broken Object Level Authorization (BOLA / IDOR)

**Source type:** AppSec remediation playbook (API-focused)  
**Related standards:** OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization; OWASP A01:2021; CWE-639  
**Reference:** https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/

## Why this matters for scanners

Automated scanners often report IDOR/BOLA when object IDs in paths or bodies can be swapped (`/accounts/{id}`, `/documents/{doc_id}`). For APIs (especially fintech), this is frequently a **high business-impact** finding: horizontal privilege escalation across customers.

## Root cause pattern

1. Authentication succeeds (user is logged in).
2. Authorization checks identity only — not **ownership / tenancy** of the target object.
3. Object identifiers are attacker-controllable (path, query, or body).

Two findings that share this root cause are still distinct if they protect different resources (accounts vs documents), but the **control design** is the same: server-side authorization on every object access.

## Exploitation sketch (for risk explanations)

- Authenticate as User A.
- Enumerate or guess IDs for User B (`ACC-1102`, `DOC-4401`).
- Replay `GET` with the foreign ID and a valid session/JWT.
- Success response with another user's PII/financial data confirms BOLA.

## Remediation (engineering checklist)

- Enforce **server-side** ownership or role checks on every read/write/delete of a resource.
- Prefer opaque server-side mappings (session → allowed resource set) over trusting client-supplied IDs alone.
- Deny by default; return 404/403 consistently (avoid oracle differences that aid enumeration).
- Add automated tests: horizontal privilege cases for every object endpoint.
- Log authorization failures with object type + actor (no sensitive payloads in logs).

## What a good answer should say

When explaining IDOR on an accounts endpoint, name the **exact method/path/parameter**, state that auth ≠ authz, and prescribe ownership validation — not only “use UUIDs” (unguessable IDs are not authorization).
