# API Security: Broken Object Level Authorization (BOLA / IDOR)

**Source type:** AppSec remediation playbook (API-focused)  
**Related standards:** OWASP API Security Top 10 — API1 Broken Object Level Authorization; OWASP A01:2021; CWE-639  
**Reference:** https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/

## Pattern

Object identifiers in path, query, or body can be swapped so User A accesses User B’s resources. Scanners flag IDOR/BOLA when auth succeeds but **ownership / tenancy** is not enforced.

Typical shapes (illustrative, not dataset-specific):

- Path objects: `/resources/{id}`, `/users/{userId}/items/{itemId}`
- Query or body IDs that select another tenant’s row

## Root cause pattern

1. Authentication succeeds (session/JWT present).
2. Authorization checks identity only — not ownership of the target object.
3. Object identifiers are attacker-controllable.

Two findings that share this root cause can still protect **different resources**, but the **control design** is the same: server-side authorization on every object access.

## Exploitation sketch

- Authenticate as User A.
- Substitute or enumerate object IDs for User B.
- Replay the request with a valid session.
- Success response with another user’s data confirms BOLA.

## Remediation checklist

- Enforce **server-side** ownership or role checks on every read/write/delete.
- Prefer server-side mappings (session → allowed resource set) over trusting client IDs alone.
- Deny by default; return 404/403 consistently (reduce enumeration oracles).
- Automated horizontal-privilege tests for every object endpoint.
- Log authorization failures with object type + actor (no sensitive payloads).

## AppSec answer guidance

Name the finding’s **method/path/parameter** from the store, state that auth ≠ authz, and prescribe ownership validation — not only “use UUIDs” (unguessable IDs are not authorization).
