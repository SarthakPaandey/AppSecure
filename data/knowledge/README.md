# Knowledge base layout

This directory is the **offline AppSec knowledge corpus** embedded on `POST /ingest`.

## Structure

```text
knowledge/
├── owasp_top10_2021/     # Assignment: OWASP Top 10 (2021) A01–A10
├── cwe/                  # Assignment: CWE defs for CWEs in the sample scan
├── appsec_guides/        # Extra: PTaaS-style playbooks (security-minded RAG)
└── README.md             # This file
```

## Why offline curated (not live scrape)?

- Deterministic demos for reviewers  
- No flaky HTML / rate limits from owasp.org or cwe.mitre.org  
- Official URLs still stored on each document for **citations**  
- Production roadmap: scheduled sync job from those sources  

## AppSec guides (beyond generic CWE text)

| Guide | Purpose |
|-------|---------|
| `api_security_bola_idor.md` | API BOLA/IDOR — auth ≠ authz |
| `jwt_none_algorithm.md` | JWT algorithm allowlist / reject `none` |
| `ssrf_cloud_metadata.md` | SSRF + cloud metadata impact |
| `sqli_parameterized_queries.md` | Parameterization-first SQLi fix |
| `authn_hardening.md` | Rate limit / password / secrets cluster |
| `scanner_finding_interpretation.md` | How a PTaaS agent should reason |
| `owasp_api_top10_pointer.md` | API Top 10 framing for fintech APIs |

These make retrieval **security-product aware**, not a generic Wikipedia-style RAG dump.
