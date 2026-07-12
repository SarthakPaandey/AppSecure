# Architecture — Vulnerability Explainer RAG (AppSecure)

Reviewer-facing design document for natural-language Q&A over **application security scan findings**.

**Thesis**

> Structured findings decide what exists. Hybrid retrieval resolves soft language. The LLM explains only verified findings, with server-validated citations.

| Related docs | Role |
|--------------|------|
| [`../README.md`](../README.md) | Runbook, API summary, measured evidence |
| [`VALIDATION.md`](VALIDATION.md) | Offline / live / Docker validation log |

---

## Table of contents

1. [Problem framing](#1-problem-framing)
2. [System context](#2-system-context)
3. [Logical architecture (detailed)](#3-logical-architecture-detailed)
4. [Data model](#4-data-model)
5. [Ingest pipeline (sequence)](#5-ingest-pipeline-sequence)
6. [Query pipeline (detailed)](#6-query-pipeline-detailed)
7. [Exact path vs soft path](#7-exact-path-vs-soft-path)
8. [Hybrid retrieval internals](#8-hybrid-retrieval-internals)
9. [Planning, routing, and scope](#9-planning-routing-and-scope)
10. [Generation and citation gate](#10-generation-and-citation-gate)
11. [Anti-hallucination stack](#11-anti-hallucination-stack)
12. [Component / package map](#12-component--package-map)
13. [Runtime configuration](#13-runtime-configuration)
14. [Deployment views](#14-deployment-views)
15. [Failure modes and fail-soft](#15-failure-modes-and-fail-soft)
16. [Tradeoffs and limitations](#16-tradeoffs-and-limitations)
17. [Security notes](#17-security-notes)

---

## 1. Problem framing

### 1.1 Product goal

PTaaS / AppSec scanners emit dense structured findings (severity, CWE, endpoint, evidence, remediation). Users ask natural language questions. The system must:

- list and filter the **complete** inventory for a scan;
- explain and remediate **only** findings that exist;
- **abstain** when the scan does not support the claim;
- attach **citations** that the server can verify.

### 1.2 Required query families

| Family | Example | Correctness risk if wrong |
|--------|---------|---------------------------|
| Inventory / count | “How many CRITICAL?” | Invented counts |
| Filter list | “A01 findings”, “payments endpoint” | Missing or extra rows |
| Explain / risk | “What’s the risk of the SSRF finding?” | Fabricated impact |
| Remediate | “How do I fix SQLi in transaction search?” | Wrong fix / wrong finding |
| Existence | “Is there RCE?” / “command injection?” | False positive presence |
| Compare / cluster | “Compare the two IDORs” | Cross-finding hallucination |

### 1.3 Why not “embed the JSON and chat”

```text
                    pure vector RAG
Question ──────────────────────────► top-k chunks ──► LLM free-form answer
                                                         │
                         fails on: full CRITICAL list, exact counts,
                         stable IDs, existence (absent classes), citations
```

| Approach | Typical failure |
|----------|-----------------|
| Embed full JSON + chat | Incomplete lists; invented endpoints/IDs |
| LLM free-form inventory | “15 CRITICAL” when there are 2 |
| SQL only | Soft phrasing (“other users’ profiles”) weak |
| Unvalidated LLM citations | Hallucinated finding IDs in text |

**Design response:** dual store (SQLite + Chroma), exact-vs-soft path split, citation gate, subtype-aware existence, fail-closed vector filters.

---

## 2. System context

External actors and systems:

```text
┌──────────────┐     HTTPS/JSON      ┌──────────────────────────────────┐
│  Engineer /  │◄───────────────────►│  AppSecure API (this service)    │
│  PTaaS UI /  │   /ingest, /query   │  FastAPI process                 │
│  curl/scripts│                     └───────────┬──────────────────────┘
└──────────────┘                                 │
                                                 │
           ┌─────────────────────────────────────┼─────────────────────────┐
           │                                     │                         │
           ▼                                     ▼                         ▼
 ┌─────────────────┐                 ┌───────────────────┐     ┌───────────────────┐
 │ Local durable   │                 │ Embedding API     │     │ Chat LLM API      │
 │ state           │                 │ ModelScope        │     │ Cerebras (or any  │
 │ • SQLite file   │                 │ Qwen3-Embedding   │     │ OpenAI-compatible)│
 │ • Chroma dir    │                 └───────────────────┘     └───────────────────┘
 │ • knowledge/*.md│
 └─────────────────┘
```

**Trust boundary:** scanner evidence fields are treated as untrusted text inside prompts. API keys live only in environment / `.env` (not in git).

---

## 3. Logical architecture (detailed)

### 3.1 Component diagram

```text
┌────────────────────────────────────────────────────────────────────────────┐
│                              FastAPI application                           │
│  ┌─────────────┐  ┌──────────────────┐  ┌─────────────────────────────┐  │
│  │ api/routes  │  │ api/schemas      │  │ main.py (lifespan: clients, │  │
│  │ /ingest     │  │ request/response │  │ BM25 warm, settings)        │  │
│  │ /query      │  └──────────────────┘  └─────────────────────────────┘  │
│  │ /health     │            │                         │                    │
│  └──────┬──────┘            │                         │                    │
│         │                   │                         │                    │
│  ┌──────▼───────────────────▼─────────────────────────▼─────────────────┐ │
│  │                     services/query_service.py                        │ │
│  │  query() essay pipeline:                                            │ │
│  │    load → route/plan → structured | soft → generate → gate           │ │
│  │  helpers: citation_select, generation_pool, tool_agent_path          │ │
│  └──────┬───────────────────┬─────────────────────┬─────────────────────┘ │
│         │                   │                     │                       │
│  ┌──────▼──────┐     ┌──────▼──────┐       ┌──────▼──────┐                │
│  │ rag/        │     │ retrieval/  │       │ clients/    │                │
│  │ router      │     │ findings_   │       │ embeddings  │                │
│  │ planner     │     │  store      │       │ llm         │                │
│  │ generator   │     │ filter_     │       └──────┬──────┘                │
│  │ citations   │     │  engine     │              │                       │
│  │ scope       │     │ hybrid      │              │                       │
│  │ prompts     │     │ bm25_index  │              │                       │
│  └─────────────┘     │ vector_     │              │                       │
│                      │  store      │              │                       │
│                      │ taxonomy    │              │                       │
│                      │ existence_  │              │                       │
│                      │  subtype    │              │                       │
│                      └──────┬──────┘              │                       │
│  ┌──────────────────┐       │                     │                       │
│  │ ingestion/       │───────┼─────────────────────┘                       │
│  │ pipeline         │       │                                             │
│  │ finding_docs     │       │                                             │
│  │ knowledge_loader │       │                                             │
│  └────────┬─────────┘       │                                             │
└───────────┼─────────────────┼─────────────────────────────────────────────┘
            │                 │
            ▼                 ▼
   ┌────────────────┐  ┌────────────────┐
   │ SQLite         │  │ Chroma         │
   │ scans +        │  │ finding +      │
   │ findings rows  │  │ knowledge docs │
   └────────────────┘  └────────────────┘
```

### 3.2 Dual-store responsibility split

```text
                    ┌─────────────────────────────┐
                    │        User question        │
                    └──────────────┬──────────────┘
                                   │
              ┌────────────────────┴────────────────────┐
              │                                         │
              ▼                                         ▼
   ┌─────────────────────┐                 ┌─────────────────────────┐
   │ EXACT / STRUCTURAL  │                 │ SOFT / SEMANTIC         │
   │                     │                 │                         │
   │ SQLite FilterEngine │                 │ BM25 ∪ Dense → RRF      │
   │ complete inventory  │                 │ phrase-aware existence  │
   │ severity, CWE, path │                 │ catalog-validated plan  │
   │ IDs, count, top-N   │                 │                         │
   └──────────┬──────────┘                 └────────────┬────────────┘
              │                                         │
              └────────────────────┬────────────────────┘
                                   ▼
                    ┌─────────────────────────────┐
                    │ Finding rows (authoritative)│
                    │ + optional knowledge chunks │
                    └──────────────┬──────────────┘
                                   ▼
                    ┌─────────────────────────────┐
                    │ Template and/or LLM explain │
                    │ → citation gate → response  │
                    └─────────────────────────────┘
```

| Store | Technology | Guarantees | Does not guarantee |
|-------|------------|------------|--------------------|
| Findings SoR | SQLite | Complete scan membership; exact filters; re-ingest | Soft paraphrase understanding |
| Vectors | Chroma | Approximate semantic neighbors; knowledge context | Full inventory completeness |

---

## 4. Data model

### 4.1 Relational (SQLite)

```text
┌──────────────────────────────┐
│ scans                        │
├──────────────────────────────┤
│ scan_id PK                   │
│ target                       │
│ scan_timestamp               │
│ ingested_at                  │
└──────────────┬───────────────┘
               │ 1
               │
               │ *
┌──────────────▼───────────────┐
│ findings                     │
├──────────────────────────────┤
│ id PK (surrogate)            │
│ scan_id FK  ─── index        │
│ finding_id  ─── unique w/    │
│                 scan_id      │
│ title, severity, cwe_id      │
│ owasp_category, endpoint     │
│ method, parameter            │
│ description, evidence_json   │
│ remediation_hint             │
└──────────────────────────────┘
```

Finding IDs are **opaque strings** from the scanner catalog (`FINDING-001`, `SHIP-AUTH-01`, `web:xss:44`, …) — not only a regex.

### 4.2 Vector documents (Chroma)

| Kind | Typical metadata | Purpose |
|------|------------------|---------|
| Finding narrative | `doc_type=finding`, `scan_id`, `source_id` (finding_id), severity/cwe… | Soft retrieval of scan rows |
| Knowledge | `doc_type` ∈ {cwe, owasp, guide, …}, `source_id` | Remediation/context after findings selected |

**Invariant:** knowledge chunks never alone justify “finding X exists.”

### 4.3 In-memory IR

- **BM25 index** over finding text fields (rebuilt on ingest / process start warm).  
- Optional **cross-encoder** shortlist rerank (disabled by default).

---

## 5. Ingest pipeline (sequence)

```text
Client                API                 IngestionPipeline           SQLite        Embed API       Chroma        BM25
  │                    │                         │                      │              │              │            │
  │ POST /ingest       │                         │                      │              │              │            │
  │ {scan, refs?}      │                         │                      │              │              │            │
  │───────────────────►│                         │                      │              │              │            │
  │                    │ ingest()                │                      │              │              │            │
  │                    │────────────────────────►│                      │              │              │            │
  │                    │                         │ replace_scan         │              │              │            │
  │                    │                         │─────────────────────►│              │              │            │
  │                    │                         │ delete vectors       │              │              │            │
  │                    │                         │ by scan_id ─────────────────────────────────────►│            │
  │                    │                         │ embed narratives     │              │              │            │
  │                    │                         │─────────────────────────────────────►│              │            │
  │                    │                         │ upsert finding docs  │              │              │            │
  │                    │                         │──────────────────────────────────────────────────►│            │
  │                    │                         │ load knowledge dir   │              │              │            │
  │                    │                         │ embed + upsert knowledge ──────────────────────────►│            │
  │                    │                         │ rebuild BM25 all findings ─────────────────────────────────────►│
  │                    │ IngestResponse          │                      │              │              │            │
  │◄───────────────────│◄────────────────────────│                      │              │              │            │
```

**Properties:** per-`scan_id` replace is idempotent; multi-scan coexistence in one DB; knowledge is offline-curated under `data/knowledge/`.

---

## 6. Query pipeline (detailed)

### 6.1 Top-level control flow

```text
                         POST /query { question, scan_id? }
                                      │
                                      ▼
                         ┌────────────────────────┐
                         │ Resolve scan_id        │
                         │ Load all findings +    │
                         │ endpoint/ID catalog    │
                         └───────────┬────────────┘
                                     │
                     empty inventory?│
                          yes ───────┼──────► fixed abstain (call /ingest)
                                     │ no
                                     ▼
                         ┌────────────────────────┐
                         │ rule_based_route       │
                         │ + soft endpoint resolve│
                         │ + catalog finding IDs  │
                         │ + decide_scope         │
                         └───────────┬────────────┘
                                     │
                    out of scope?    │
                          yes ───────┼──────► product-boundary refusal
                                     │ no
                                     ▼
                         ┌────────────────────────┐
                         │ optional SemanticPlan  │
                         │ (if rules not confident)│
                         │ validate + merge       │
                         └───────────┬────────────┘
                                     │
              ┌──────────────────────┴──────────────────────┐
              │ precision / structured?                     │ soft
              ▼                                             ▼
   ┌─────────────────────┐                    ┌─────────────────────────┐
   │ apply_filters       │                    │ optional tool agent     │
   │ (FilterEngine)      │                    │ (default OFF)           │
   │ subtype existence   │                    │ else HybridRetriever    │
   │ filter if needed    │                    │ + subtype existence     │
   └──────────┬──────────┘                    └────────────┬────────────┘
              │                                            │
              │                              empty + existence/explain…?
              │                                   yes ─────┼──► abstain
              ▼                                            │ no
   ┌─────────────────────┐                                 ▼
   │ generator templates │                    ┌─────────────────────────┐
   │ (count/list/exist)  │                    │ prepare pool + generate │
   │ or dynamic synth    │                    │ (LLM or template soft)  │
   └──────────┬──────────┘                    └────────────┬────────────┘
              │                                            │
              └──────────────────────┬─────────────────────┘
                                     ▼
                         ┌────────────────────────┐
                         │ select citations       │
                         │ gate_citations         │
                         │ build_citations        │
                         └───────────┬────────────┘
                                     ▼
                              QueryResponse
```

### 6.2 Orchestrator entry (`QueryService.query`)

Readable stage list (matches code helpers):

1. Load scan + catalogs  
2. `_build_route_and_plan`  
3. `_execute_structured_query` (or `None` if soft)  
4. Unknown-path abstain (when applicable)  
5. `try_tool_agent` (default off → always skip)  
6. `_execute_semantic_query`  
7. `_generate_response` + citation selection/gate  

---

## 7. Exact path vs soft path

### 7.1 When the exact path wins

Precision mode is true when filters are high-confidence, e.g.:

- `want_count` / `top_n`  
- severity lists for list/existence  
- strict endpoints / finding IDs  
- include/exclude phrases or topics for list  
- path-parameter shape filters  

Then:

```text
all findings (scan) ──► FilterEngine ──► rows ──► template/LLM ──► gate
```

**No BM25/dense required** for pure inventory templates.

### 7.2 Soft path

Used for free-text explain/remediate/compare and soft existence without hard slots:

```text
question ──► (planner?) ──► hybrid retrieve ──► knowledge ──► generate ──► gate
```

### 7.3 LLM call budget (defaults)

| Path | Chat LLM calls |
|------|---------------:|
| Count / CRITICAL list / A01 / top-N inventory | **0** |
| Explain/fix with clear structure | **1** (generator) |
| Soft semantic | **2** (planner + generator) |
| Unsupported existence | **0–1** |
| Max normal (+ optional repair) | **≤3** |

Scope LLM and tool agent: **off by default**.

---

## 8. Hybrid retrieval internals

```text
                         free-text question
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
 ┌─────────────┐         ┌─────────────┐         ┌─────────────┐
 │ Phrase /    │         │ BM25        │         │ Dense       │
 │ topic seeds │         │ inverted    │         │ Chroma      │
 │ from text + │         │ index       │         │ query with  │
 │ taxonomy    │         │ (lexical)   │         │ where:      │
 └──────┬──────┘         └──────┬──────┘         │ scan_id +   │
        │                       │                │ doc_type    │
        │                       │                └──────┬──────┘
        │                       │                       │
        │                       │         embed fail ───┤ empty (fail soft)
        │                       │                       │
        └───────────────────────┴───────────────────────┘
                                │
                                ▼
                     Reciprocal Rank Fusion (RRF)
                                │
                                ▼
                     light lexical / severity boost
                     (optional CE shortlist: OFF by default)
                                │
                                ▼
                     FindingRecord list (scan-bound)
                                │
                                ▼
                     existence_subtype filter (if specific vuln named)
```

**RRF idea:** combine ranked lists without learning weights — good default for lexical + semantic union.

**Isolation:** dense queries use Chroma `where` including `scan_id`. On filter failure: **return no hits** (fail closed). Never retry unfiltered.

---

## 9. Planning, routing, and scope

### 9.1 Types (roles)

| Type | Role |
|------|------|
| `RouteResult` | Explicit user syntax / rules output |
| `QueryPlan` | Optional semantic interpretation (`in_scope`, slots) |
| `FilterSpec` | Input to SQLite FilterEngine |

Adapters only: `route_to_filter_spec`, `merge_plan_into_route`, catalog ID/endpoint resolvers. No full schema rename.

### 9.2 Rules

`rule_based_route` extracts:

- severities / exclusions  
- CWE / OWASP  
- paths and soft endpoint tokens  
- count / top-N  
- topics from taxonomy  
- intent (list, explain, remediation, existence, compare, cluster, …)  

### 9.3 Planner policy

```text
rules confident? ──yes──► skip planner
       │
       no
       ▼
   LLM → QueryPlan JSON
       │
       ├─ high-conf in_scope=false ──► refuse
       ├─ malformed / timeout / low-conf out ──► fail open → retrieve
       └─ valid ──► validate vs catalog → merge (rules win hard slots)
```

Planner **must not** invent finding IDs not in catalog / not typed by the user.

### 9.4 Scope

1. Structural scan slots → in scope (no LLM)  
2. Obvious junk (weather, joke, …) → refuse  
3. Optional scope LLM if enabled (default **false**)  
4. Else fail open to retrieval; unsupported claims abstain later  

---

## 10. Generation and citation gate

### 10.1 Generator modes

| Mode | Source field | Use |
|------|--------------|-----|
| Structured templates | `answer_source=structured` | Counts, lists, existence yes, clusters |
| LLM JSON | `answer_source=llm` | Explain / remediate / compare |
| Fail-soft template | `answer_source=template` | LLM timeout / invalid JSON |
| Abstain | `answer_source=abstain` | No support / out of scope / empty store |

Templates bind **endpoint + parameter + severity + remediation_hint** from store rows — no sample-specific prose packs.

### 10.2 Citation pipeline

```text
generator findings_referenced
        │
        ▼
 validate ⊆ retrieved/filtered set
        │
        ▼
 intent-aware selection (list keeps full set; explain tightens)
        │
        ▼
 multi-topic compare may restore retrieval union if model under-cites
        │
        ▼
 gate_citations (strip unknown IDs from text + refs)
        │
        ▼
 build_citations (findings + optional knowledge refs)
```

---

## 11. Anti-hallucination stack

Layered defense (outer → inner):

```text
1. Product scope refuse (junk / empty store)
2. Exact FilterEngine (cannot invent rows)
3. Existence + subtype gate (parent family ≠ subtype presence)
4. Hybrid only returns scan-bound records
5. Generator prompts: only FINDINGS/KNOWLEDGE context
6. Server citation gate (IDs must be allowed)
7. Fail-closed vector filters (no cross-scan leak on error)
8. Fail-soft templates (no hang → invent loop)
```

### 11.1 Specific vs broad existence

| Question style | Behavior |
|----------------|----------|
| “Is there **command injection**?” | Require direct support (wording / CWE-78); SQLi/XSS insufficient → **abstain** if none |
| “Which **injection** findings?” | Broad family listing may return SQLi/XSS/SSRF union |
| “Is there **SQL injection**?” | Direct SQLi / CWE-89 → e.g. FINDING-001 |

Implemented in `app/retrieval/existence_subtype.py` + applied on structured and hybrid existence paths.

---

## 12. Component / package map

```text
app/
├── main.py                 # lifespan: settings, embed/LLM clients, BM25 warm
├── config.py               # env-backed Settings
├── api/
│   ├── routes.py           # HTTP endpoints
│   └── schemas.py          # Pydantic contracts
├── clients/
│   ├── embeddings.py       # OpenAI-compatible embed + timeouts
│   └── llm.py              # chat complete + tool path + FakeLLM
├── db/
│   ├── models.py           # Scan, Finding
│   └── session.py
├── ingestion/
│   ├── pipeline.py         # orchestrate ingest
│   ├── finding_documents.py
│   └── knowledge_loader.py
├── retrieval/
│   ├── findings_store.py   # SQL access layer
│   ├── filter_engine.py    # FilterSpec + apply_filters
│   ├── hybrid.py           # soft retrieval orchestration
│   ├── bm25_index.py
│   ├── vector_store.py     # Chroma fail-closed query
│   ├── taxonomy.py         # AppSec topics
│   ├── existence_subtype.py
│   ├── synonyms.py         # light phrase extraction
│   ├── endpoint_utils.py
│   ├── rerank.py / cross_encoder.py  # optional CE
├── rag/
│   ├── router.py           # rules
│   ├── planner.py / plan_schema.py
│   ├── generator.py / prompts.py
│   ├── citations.py
│   ├── scope.py
│   └── tools.py / tool_agent.py     # optional
└── services/
    ├── query_service.py    # main pipeline
    ├── citation_select.py
    ├── generation_pool.py
    ├── tool_agent_path.py
    └── pipeline_common.py
```

---

## 13. Runtime configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `USE_SEMANTIC_PLANNER` | true | Soft NL → QueryPlan |
| `USE_DYNAMIC_SYNTHESIS` | true | LLM narrative |
| `USE_LLM_SCOPE_GATE` | **false** | Dedicated scope LLM |
| `USE_TOOL_AGENT` | **false** | Multi-round tools |
| `RERANK_MODE` | **light** | RRF + light boosts |
| `CROSS_ENCODER_ENABLED` | **false** | Optional CE |
| `LLM_TIMEOUT_S` | 20 | Chat timeout |
| `LLM_MAX_RETRIES` | 0 | Provider retries |
| `EMBED_TIMEOUT_S` | 10 | Embed timeout |
| `EMBED_MAX_RETRIES` | 0 | Embed retries |
| `SQLITE_PATH` / `CHROMA_PATH` / `KNOWLEDGE_DIR` | under `./data` | Persistence |

Full list: `.env.example`.

---

## 14. Deployment views

### 14.1 Local process

```text
uvicorn app.main:app
  ├── data/app.db
  ├── data/chroma/
  └── env keys → ModelScope + Cerebras
```

### 14.2 Docker Compose

```text
docker compose up --build
  container: uvicorn :8000
  volumes: sqlite-data, chroma-data
  image bakes: app/, knowledge/, sample_findings.json, heldout_scan.json
  env_file: .env
```

---

## 15. Failure modes and fail-soft

| Failure | Behavior |
|---------|----------|
| No findings ingested | Fixed message: call `/ingest` |
| Out of product scope | Fixed refusal |
| Existence unsupported | `abstained=true`, empty refs |
| Specific subtype absent | Abstain (even if parent family has rows) |
| Chroma filtered query error | Empty hits (fail closed) |
| Embed timeout/error | Dense empty; BM25/SQL continue |
| LLM timeout / bad JSON | Row-bound **template** answer + valid IDs |
| Planner error | Fail open to retrieval |

---

## 16. Tradeoffs and limitations

| Decision | Benefit | Cost |
|----------|---------|------|
| SQLite first | Exact inventory, zero ops | Soft NL needs hybrid |
| Curated taxonomy | Predictable AppSec classes | Incomplete open-domain NL |
| Rules + optional planner | Low LLM cost on hard ops | Soft mis-routes possible |
| Strict citations | No free-form ID invent | Tighter answers |
| Provider timeouts | Bounded latency | More `template` sources under load |
| Single process demo | Simple take-home | No multi-tenant auth |

**Limitations (honest)**

1. Soft paraphrases can miss or over-retrieve.  
2. Taxonomy is curated, not live MITRE.  
3. Orchestrator is modular but still the policy center.  
4. Latency is provider-dependent (not an SLA).  
5. Out of scope: multi-tenant auth, audit, K8s, frontend.

**Natural product next steps**

- Broader multi-scan eval + CI budgets  
- Stage-level metrics  
- Tenant isolation  
- Cached / local embeddings  

---

## 17. Security notes

- Treat `evidence` as untrusted.  
- Never commit `.env` or keys.  
- Citations validated against selected scan only.  
- Vector filters fail closed on error.  

---

*Architecture document is authoritative for system design. Runbooks and numbers live in the README and VALIDATION.md.*
