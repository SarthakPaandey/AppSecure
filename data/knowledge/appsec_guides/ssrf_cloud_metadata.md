# SSRF: Unvalidated Server-Side URL Fetches

**Source type:** AppSec remediation playbook  
**Related:** OWASP A10:2021 SSRF; CWE-918; OWASP API Security (SSRF abuse)  
**Reference:** https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/

## Pattern (what scanners mean)

The application performs an **HTTP(S) request from the server** using a client-controlled URL (body, query, or header). Without a destination policy, that request can reach places the client cannot.

## Impact classes (vector retrieval should prefer the relevant section)

### Cloud instance metadata (IMDS)
- Link-local metadata endpoints (e.g. `http://169.254.169.254/` on many clouds).
- **AWS IMDSv1** is often trivially reachable via SSRF; **IMDSv2** requires a session token header (harder via simple GET SSRF).
- GCP / Azure expose analogous metadata services with different hostnames and headers.
- Successful metadata access may yield temporary credentials, role ARNs, or project identity.

### Internal services and databases
- Private VPC hostnames, admin panels, package registries, Redis/HTTP APIs, Kubernetes APIs.
- Port scanning and service fingerprinting from the app tier’s network position.

### Loopback and local agents
- `127.0.0.1` / `localhost` services (debug ports, sidecars, cloud agent sockets).
- Bypass of “external only” mental models when the app co-hosts tools.

## Root cause pattern

1. User input becomes the request target (URL, host, or redirect chain).
2. No allowlist of schemes/hosts; no block on private, loopback, or link-local ranges.
3. Response body (or error text) may be reflected to the client, confirming reachability.

## Exploitation sketch (generic)

1. Authenticate if the feature requires it.
2. Point the URL parameter at metadata, internal, or loopback targets.
3. Observe reflected content, timing, or error differences.
4. Escalate via stolen cloud credentials or internal service abuse.

## Remediation checklist

- **Deny by default** egress; allowlist schemes (`https`) and destinations.
- Block private, loopback, link-local, and metadata IP ranges (IPv4/IPv6); resolve DNS and re-check (DNS rebinding).
- Prefer **IMDSv2** / hop-limit hardening so app processes cannot trivially reach metadata.
- Disable or strictly validate redirects; do not proxy raw responses to clients.
- Timeouts, size limits, and SSRF-focused tests in CI.

## AppSec answer guidance

When answering from a scan finding, **bind risk and remediation to the finding’s endpoint and parameter fields** from the store. Explain impact paths (metadata, internal, loopback) using this pattern guide — do not invent parameter names that are not on the finding row.
