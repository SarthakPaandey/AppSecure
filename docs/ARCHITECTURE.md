# Architecture

Vulnerability Explainer RAG (AppSecure) — design for natural-language Q&A over **application security scan findings**.

**Thesis**

> Structured findings decide what exists. Hybrid retrieval resolves soft language. The LLM explains only verified findings, with server-validated citations.

This document is the reviewer-facing architecture reference. For measured test evidence, see [`VALIDATION.md`](VALIDATION.md).

---

## 1. Problem and design constraints

### 1.1 What the product must do

| Capability | Example |
|------------|---------|
| Inventory / filter | “What are all CRITICAL findings?” |
| Explain | “Explain the IDOR on accounts” |
| Remediate | “How do I fix the SQL injection…?” |
| Existence | “Is there RCE?” → abstain if none |
| Cross-ref | “Which findings map to OWASP A01?” |
| Compare / summarize | Multi-finding narrative from store rows |

### 1.2 Why pure vector RAG is not enough

| Approach | Failure mode |
|----------|----------------|
| Embed full JSON + chat | Incomplete CRITICAL lists; invented IDs/endpoints |
| LLM free-form counts | “15 CRITICAL” when there are 2 |
| SQL only | Weak on soft phrasing (“other users’ data”) |
| Unvalidated LLM citations | Hallucinated `FINDING-*` in answers |

**Solution:** dual store + path split (exact vs soft) + citation gate + existence rules.

---

## 2. High-level architecture

```text
                    ┌─────────────────────────────────────┐
                    │           FastAPI (app)             │
                    │  POST /ingest  POST /query          │
                    │  GET /health   GET /scans/...       │
                    └─────────────────┬───────────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              ▼                       ▼                       ▼
     ┌────────────────┐    ┌────────────────────┐   ┌─────────────────┐
     │ Ingestion      │    │ QueryService       │   │ Config /        │
     │ Pipeline       │    │ (orchestrator)     │   │ OpenAI-compat   │
     └───────┬────────┘    └─────────┬──────────┘   │ clients         │
             │                       │              └────────┬────────┘
             │                       │                       │
     ┌───────▼────────┐    ┌─────────▼──────────┐            │
     │ SQLite         │    │ Router + Planner   │◄───────────┤
     │ (findings)     │◄───│ FilterEngine       │   embed /  │
     │ system of      │    │ HybridRetriever    │   chat     │
     │ record         │    │ Generator          │            │
     └────────────────┘    │ Citation gate      │            │
                           └─────────┬──────────┘            │
                                     │                       │
                           ┌─────────▼──────────┐   ┌────────▼────────┐
                           │ Chroma             │   │ External APIs   │
                           │ findings +         │   │ ModelScope emb  │
                           │ knowledge vectors  │   │ Cerebras LLM    │
                           │ fail-closed where  │   └─────────────────┘
                           └────────────────────┘
```

### 2.1 Dual store

| Store | Technology | Role |
|-------|------------|------|
| **System of record** | SQLite (SQLAlchemy) | Full inventory, exact filters (severity, CWE, endpoint, IDs), multi-scan isolation via `scan_id` |
| **Semantic / knowledge** | Chroma (persistent) | Finding narratives + OWASP/CWE/playbook chunks; metadata filters (`scan_id`, `doc_type`) |

SQLite answers “what is in this scan?” completely.  
Chroma answers “which chunks are similar to this soft question?”  
Neither alone solves both inventory and soft language.

---

## 3. End-to-end query pipeline

```text
Question + scan_id
  → Load selected scan + catalog (IDs, endpoints)
  → Rule-based structural parse
  → Catalog-aware finding IDs (any scheme present in the scan)
  → Scope: structural in / obvious junk out
  → Exact / precision path?
       Yes → FilterEngine (SQLite set algebra)
            → Inventory or existence template
            → Citation gate
       No  → Optional semantic planner (ambiguous only)
            → Validate plan against catalog (rules win on explicit slots)
            → High-conf in_scope=false → refuse
            → Planner fail / low-conf → fail open to retrieval
            → BM25 ∪ dense → RRF (CE off by default)
            → Optional tool agent (off by default)
            → Grounded generator or row-bound template (fail-soft)
            → Citation gate
  → Response { answer, citations, findings_referenced, abstained, … }
```

### 3.1 Stage responsibilities

| Stage | Module(s) | Responsibility |
|-------|-----------|----------------|
| HTTP | `app/api/` | Schemas, thin routes |
| Ingest | `app/ingestion/` | Upsert SQLite, embed findings, index knowledge, rebuild BM25 |
| Route | `app/rag/router.py` | Explicit operators: severity, CWE, count, top-N, intent cues |
| Plan | `app/rag/planner.py`, `plan_schema.py` | Soft NL → structured slots; never final answers |
| Scope | `app/rag/scope.py` | Product boundary (rules first; optional scope LLM off by default) |
| Filter | `app/retrieval/filter_engine.py` | Deterministic set algebra on finding rows |
| Hybrid IR | `app/retrieval/hybrid.py`, `bm25_index.py` | BM25 + dense + RRF; phrase-aware existence |
| Subtype existence | `app/retrieval/existence_subtype.py` | Specific vulns need **direct** row support |
| Generate | `app/rag/generator.py` | Templates for inventory; LLM for narrative |
| Citations | `app/rag/citations.py`, `services/citation_select.py` | Server-side ID validation / stripping |
| Orchestrate | `app/services/query_service.py` (+ helpers) | Essay pipeline composition |

### 3.2 Hard vs soft questions

| Type | Example | Path | Typical LLM calls |
|------|---------|------|------------------:|
| Hard | “How many CRITICAL?” | FilterEngine + template | **0** |
| Structural list | “A01 findings” | SQL / filters | **0** |
| Existence absent | “Is there RCE?” | Existence search → empty → abstain | **0–1** |
| Soft explain | “Risk of SSRF…” | Hybrid + generator | **1–2** |
| Ambiguous soft | Unusual NL | Planner + hybrid + generator | **2** (max ~3 with repair) |

Dedicated multi-round **tool agent** and **scope LLM** exist but are **off by default**.

---

## 4. Anti-hallucination controls (layered)

Prompts alone are **not** a control.

| Control | Behavior |
|---------|----------|
| **Store as truth** | Only rows in the selected scan can be asserted as findings |
| **Existence abstention** | No supporting rows → `abstained=true`, no invented IDs |
| **Subtype existence** | “Command injection” needs command-injection / CWE-78 evidence — not SQLi/XSS via parent “injection” |
| **Citation gate** | `findings_referenced` ⊆ allowed retrieved/filtered IDs; unknown IDs stripped |
| **Scan isolation** | Filters and vector `where` always include `scan_id` |
| **Fail-closed vectors** | Filtered Chroma query failure → empty hits, **never** bare unfiltered retry |
| **Fail-soft generation** | LLM/embed timeout → BM25/SQL + **store-bound templates**, not multi-minute hang |
| **Knowledge ≠ presence** | CWE/OWASP playbooks explain verified rows; they do not prove a finding exists |
| **Untrusted evidence** | Scanner request/response snippets treated as untrusted in prompts |

### 4.1 Specific vs broad existence

```text
specific subtype existence  → strict direct support (title/description/CWE)
broad family listing        → union of family findings OK
```

| Requested | Direct support examples |
|-----------|-------------------------|
| Command injection | Command/OS/shell wording, `CWE-78` |
| SQL injection | SQL injection wording, `CWE-89` |
| XSS | XSS / cross-site scripting, `CWE-79` |
| SSRF | SSRF wording, `CWE-918` |
| RCE | Explicit RCE / code execution wording |

---

## 5. Retrieval design

### 5.1 FilterEngine (exact path)

`FilterSpec` dimensions (AND across dimensions, OR within phrases where configured):

- Severities include/exclude  
- CWE / OWASP  
- Endpoint substrings (strict when catalog-resolved)  
- Finding IDs (catalog-aware, any ID scheme)  
- Topics / include–exclude phrases  
- Path-parameter shape, top-N, count  

Used for inventory, many existence checks, and high-precision lists.

### 5.2 Hybrid free-text (soft path)

```text
BM25 (lexical)  ∪  dense vectors (semantic)  →  Reciprocal Rank Fusion
```

- **BM25:** paths, acronyms, exact tokens  
- **Dense:** paraphrase (“other users’ accounts”)  
- **RRF:** simple, no learned fusion weights  
- **Cross-encoder:** optional (`CROSS_ENCODER_ENABLED=false` by default)  

Dense/embed failure fails **soft**: BM25 + phrases only.

### 5.3 Knowledge retrieval

OWASP Top 10, CWE notes, and AppSec playbooks are embedded with `doc_type` metadata.  
Used to improve **explanation/remediation quality** after findings are selected — not as proof of presence.

---

## 6. Planning and routing policy

### 6.1 Rules first

`rule_based_route` extracts high-precision surface form:

- `CRITICAL` / `not HIGH`  
- `CWE-89`, `A01`  
- Paths `/api/...`  
- Count / top-N language  
- Intent cues (explain, remediate, existence, compare, cluster)  

### 6.2 Planner (optional, ambiguous only)

When rules are not confident:

1. LLM emits `QueryPlan` JSON (filters/concepts only — **no final answer**)  
2. Validate against scan catalog (endpoints, finding IDs)  
3. Merge with rules: **explicit structural slots always win**  
4. `in_scope=false` high confidence → refuse  
5. Malformed / timeout / low-conf out → **fail open** to retrieval  

### 6.3 Catalog-aware IDs

After scan load, finding IDs are matched from the live catalog — not only `FINDING-\d+`  
(e.g. `SHIP-AUTH-01`, `web:xss:44`, `VULN_2026_91`).

---

## 7. Generation and response contract

### 7.1 Generators

| Mode | When | Behavior |
|------|------|----------|
| Structured templates | Counts, lists, existence yes-set, clusters | Deterministic from store fields |
| LLM JSON | Explain / remediate / compare (dynamic on) | Bound to FINDINGS + KNOWLEDGE blocks |
| Template fail-soft | LLM timeout / bad JSON | Row-bound narrative from store fields |

### 7.2 API response (conceptual)

```json
{
  "answer": "...",
  "citations": [{ "type": "finding|reference", "id": "...", "title": "..." }],
  "findings_referenced": ["FINDING-001"],
  "query_intent": "remediation",
  "grounded": true,
  "abstained": false,
  "latency_ms": 800,
  "answer_source": "structured|llm|template|abstain",
  "model_used": "gemma-4-31b or null",
  "scan_id": "scan-20260324-001"
}
```

`answer_source=template` after provider failure is intentional fail-soft, not silent invention.

---

## 8. Ingestion

```text
POST /ingest { scan, optional reference_documents }
  → replace_scan in SQLite (idempotent per scan_id)
  → delete prior finding vectors for that scan_id
  → embed finding narratives → Chroma
  → upsert knowledge dir (OWASP / CWE / guides)
  → rebuild BM25 over all findings
```

Knowledge is offline-curated for deterministic demos; production would sync MITRE/OWASP on a schedule.

---

## 9. Module map

```text
app/
  api/           HTTP routes + Pydantic schemas
  clients/       Embeddings + chat LLM (timeouts, fail-soft)
  db/            SQLAlchemy models + session
  ingestion/     Pipeline, finding documents, knowledge loader
  retrieval/
    findings_store.py    SQLite access
    filter_engine.py     Exact set algebra
    hybrid.py            BM25 + dense + RRF orchestration
    bm25_index.py        Lexical index + RRF helper
    existence_subtype.py Strict subtype existence
    taxonomy.py          AppSec topics → keywords/CWEs
    vector_store.py      Chroma wrapper (fail-closed filters)
  rag/
    router.py, planner.py, plan_schema.py
    generator.py, prompts.py, citations.py
    scope.py, tools.py, tool_agent.py (optional path)
  services/
    query_service.py     Main pipeline
    citation_select.py   Post-gen citation policy
    generation_pool.py   Finding pool caps / seeding
    tool_agent_path.py   Optional agent isolation
    pipeline_common.py   Response helpers
```

---

## 10. Configuration (defaults)

| Knob | Default | Meaning |
|------|---------|---------|
| `USE_SEMANTIC_PLANNER` | true | Soft NL planning |
| `USE_DYNAMIC_SYNTHESIS` | true | LLM narrative |
| `USE_LLM_SCOPE_GATE` | **false** | Dedicated scope LLM off |
| `USE_TOOL_AGENT` | **false** | Multi-round tools off |
| `RERANK_MODE` | **light** | RRF + light lexical |
| `CROSS_ENCODER_ENABLED` | **false** | Optional CE |
| `LLM_TIMEOUT_S` | 20 | Chat hang cap |
| `EMBED_TIMEOUT_S` | 10 | Embed hang cap |

See `.env.example`.

---

## 11. Evaluation approach

| Layer | Purpose |
|-------|---------|
| Unit tests (fakes) | Filters, citations, isolation, subtypes, fail-soft |
| Sample scan | Assignment-shaped demo |
| Held-out scan | Different domain + ID schemes (`SHIP-AUTH-01`, …) |
| Live suite | `scripts/live_validate.py` against real providers |
| Docker | `docker compose up --build` + health + ingest smoke |

Emphasize **store-coupling** over sample memorization. Measured numbers and command logs: [`VALIDATION.md`](VALIDATION.md).

---

## 12. Tradeoffs and limitations

| Tradeoff | Choice | Cost |
|----------|--------|------|
| Exact inventory | SQLite first | Soft NL needs hybrid + taxonomy |
| Soft language | Rules + optional planner + BM25/dense | Unusual paraphrases can miss |
| Anti-hallucination | Strict gates | Fewer “creative” answers |
| Latency | Timeouts + templates | Style shifts to template under provider stress |
| Scope | Single-process demo | No multi-tenant auth/audit |

**Known limitations**

1. Taxonomy and intent rules are curated, not complete NLU.  
2. Orchestrator is modular but still centralized.  
3. Latency depends on embedding/LLM providers (not an SLA).  
4. Soft paraphrases can abstain or over-retrieve; specific existence is stricter than broad listing.  
5. Out of take-home scope: multi-tenant auth, live MITRE sync, K8s, frontend.

**Natural next steps (product)**

- Broader multi-scan eval sets and CI latency budgets  
- Stage-level observability  
- Tenant isolation and audit  
- Cached / local embeddings for demos  

---

## 13. Security notes

- Treat scanner evidence as attacker-controlled text in prompts.  
- Never commit `.env` or API keys.  
- Citations are validated against the selected scan’s findings only.  
- Vector metadata filters fail closed on error.

---

*This architecture document is authoritative for system design. The root README covers runbooks and measured smoke results; VALIDATION.md records offline/live/Docker evidence.*
