# SSRF: User-Controlled URLs and Cloud Metadata

**Source type:** AppSec remediation playbook  
**Related:** OWASP A10:2021 SSRF; CWE-918; OWASP API Security (SSRF-related abuse)  
**Reference:** https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/

## Why this is high risk in cloud / fintech APIs

Document import, webhook preview, and “fetch URL” features often cause the **server** to request attacker-chosen destinations. From the server’s network position, that can reach:

- Link-local cloud metadata (`http://169.254.169.254/`) → temporary credentials / keys  
- Internal admin panels, Redis, package registries, k8s APIs  
- Port scanning of the internal network  

Evidence that returns metadata-like content (e.g., `AccessKeyId`) is a strong signal of impact, not a theoretical issue.

## Root cause pattern

- Application takes `source_url` (or similar) from the client.
- Performs HTTP(S) fetch without destination policy.
- Returns response body (or part of it) to the client.

## Exploitation sketch

1. Authenticate if required.
2. `POST /documents/import` with `source_url=http://169.254.169.254/latest/meta-data/...` (or internal hosts).
3. Observe whether the app returns internal content or errors that confirm reachability.
4. Escalate via stolen cloud credentials or internal service abuse.

## Remediation checklist

- **Deny by default** egress; allowlist schemes (`https`) and destinations.
- Block private, loopback, link-local, and metadata IP ranges (IPv4/IPv6); resolve DNS and re-check (DNS rebinding).
- Disable or strictly validate redirects.
- Do not proxy raw responses to clients; store sanitized content.
- Network segmentation: app tier should not need broad access to metadata/IMDS (use IMDSv2 / hop limits where applicable).
- Timeouts, size limits, and SSRF-focused tests in CI.

## AppSec answer guidance

When asked about SSRF risk, explain **impact paths** (metadata credentials, internal services), not only “validate input.” Name the parameter (`source_url`) and endpoint from the finding.
