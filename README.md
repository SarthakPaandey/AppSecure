# Vulnerability Explainer RAG Agent (AppSecure)

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![SQLite](https://img.shields.io/badge/SQLite-SoR-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Chroma](https://img.shields.io/badge/Chroma-vectors-FF6F61?style=for-the-badge)](https://www.trychroma.com/)
[![Tests](https://img.shields.io/badge/tests-148_passed-2ea44f?style=for-the-badge)](docs/VALIDATION.md)
[![Live suite](https://img.shields.io/badge/live-43%2F43-2ea44f?style=for-the-badge)](docs/VALIDATION.md)
[![License](https://img.shields.io/badge/use-take--home-6e7781?style=for-the-badge)](#license--assignment)

RAG-backed **FastAPI** service for natural-language Q&A over **application security scan results** — with **citations**, **hybrid retrieval**, and **hard anti-hallucination controls**.

Think of this as the backend for *“talk to your scan results”* in a PTaaS dashboard: list, explain, remediate, compare, and **abstain** when the scan does not support the claim.

> [!IMPORTANT]
> **Thesis** — Structured findings decide what exists. Hybrid retrieval resolves soft language. The LLM explains only verified findings.

| Layer | Choice |
|:------|:-------|
| **API** | FastAPI — `POST /ingest`, `POST /query`, `GET /health`, `GET /scans/{id}/findings` |
| **Findings store** | **SQLite** — system of record (complete inventory) |
| **Vector store** | **Chroma** — findings + knowledge; **fail-closed** metadata filters |
| **Embeddings** | `Qwen/Qwen3-Embedding-8B` (ModelScope, OpenAI-compatible) |
| **Chat LLM** | Cerebras `gemma-4-31b` (or any OpenAI-compatible base URL) |
| **Retrieval** | SQL `FilterEngine` + **BM25 ∪ dense → RRF** (cross-encoder off by default) |
| **Knowledge** | OWASP Top 10 2021 · CWEs · AppSec playbooks |
| **Docs** | [`ARCHITECTURE.md`](docs/ARCHITECTURE.md) · [`VALIDATION.md`](docs/VALIDATION.md) |

<p align="center">
  <a href="#quick-start"><strong>Quick start</strong></a> ·
  <a href="#docker"><strong>Docker</strong></a> ·
  <a href="#query-pipeline"><strong>Pipeline</strong></a> ·
  <a href="#anti-hallucination"><strong>Anti-hallucination</strong></a> ·
  <a href="docs/ARCHITECTURE.md"><strong>Architecture</strong></a> ·
  <a href="docs/VALIDATION.md"><strong>Validation</strong></a>
</p>

<details>
<summary><strong>Table of contents</strong></summary>

1. [Why this architecture](#why-this-architecture)
2. [Design tradeoffs](#design-tradeoffs)
3. [System overview](#system-overview)
4. [Query pipeline](#query-pipeline)
5. [Anti-hallucination](#anti-hallucination)
6. [Knowledge base](#knowledge-base)
7. [Quick start](#quick-start)
8. [Docker](#docker)
9. [API reference](#api-reference)
10. [Configuration](#configuration)
11. [Project layout](#project-layout)
12. [Tests and measured evidence](#tests-and-measured-evidence)
13. [Sample questions](#sample-questions)
14. [Evaluation approach](#evaluation-approach)
15. [Known limitations](#known-limitations)
16. [Security notes](#security-notes)

</details>

---

## Why this architecture

Scanner findings are **authoritative structured records**. Pure top‑k vector RAG over JSON fails on full inventory, existence checks, and stable citations.

> [!TIP]
> **Rule of thumb:** use **SQL** when the question is exact; use **hybrid IR + LLM** when the language is soft; **never** let the model invent inventory.

| Approach | Failure mode on this problem |
|:---------|:-----------------------------|
| Embed JSON + chat | Misses full CRITICAL list; invents vulns and IDs |
| LLM free-form inventory | “15 CRITICAL” when there are 2 |
| SQL only | Weak on soft phrasing (“other users’ profiles”) |
| Unvalidated LLM citations | Hallucinated `FINDING-*` in the answer text |
| **This hybrid** | Exact ops from SQLite; soft questions via hybrid IR + grounded LLM |

Full diagrams, sequences, and module map: **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)**.

---

## Design tradeoffs

Engineering choices below are deliberate. Each row is **benefit vs cost** — not a claim of production completeness.

### Storage and data

| Decision | Tradeoff (one line) |
|:---------|:--------------------|
| **SQLite as system of record** | Exact filters, complete inventory, zero infra — not multi-writer / multi-tenant production scale. |
| **Chroma (local, persistent)** | Zero-ops vector store for demos — not a managed multi-tenant vector service. |
| **Single Chroma collection** (findings + knowledge) | Simpler ingest and one embed path — isolation relies on metadata filters (`scan_id`, `doc_type`) that **fail closed**, not separate physical indexes. |
| **Replace-scan on ingest** | Clean re-demo and idempotent reloads — no concurrent partial updates of a live scan. |
| **Assignment-shaped JSON schema** | Any **N** findings of that shape work — arbitrary scanner exports need an external mapper. |

### Knowledge indexing

| Decision | Tradeoff (one line) |
|:---------|:--------------------|
| **Whole-document knowledge vectors** | Bundled CWE / OWASP / playbook files are already topic-sized, so one vector per file keeps citation IDs stable and simple. |
| **No heading / token chunking by default** | Avoids chunk-ID machinery on a compact curated corpus — large uploaded PDFs would need section-aware, token-bounded chunks in production. |
| **Offline curated knowledge** | Deterministic demos and citations — not live MITRE/OWASP sync. |
| **Playbook topic tags** | Improves hybrid ranking with domain keywords — hand-curated, not learned. |
| **Knowledge never proves presence** | Guides explain verified findings only — they cannot invent a finding that is not in SQLite. |

### Query path and LLM use

| Decision | Tradeoff (one line) |
|:---------|:--------------------|
| **Filter-first hybrid** | SQL for exact inventory; hybrid IR + LLM for soft language — soft NL is never as deterministic as SQL. |
| **No LLM for counts / full lists** | Reproducible, auditable inventory — model never “remembers” the wrong CRITICAL set. |
| **Planner only when rules are not confident** | Saves latency and stops the model rewriting explicit HIGH / path filters — soft paraphrases still need a plan. |
| **Generator for narrative only** | Explain / remediate / compare / risk get grounded prose even when routing is clear — inventory stays template/SQL (0 chat LLM). |
| **No dedicated scope LLM (default off)** | Fewer calls and disagreement points — product boundary uses rules + planner `in_scope` + grounded abstention. |
| **Planner fail-open** | Malformed JSON, timeouts, or low-confidence “out of scope” continue to retrieval rather than false-refuse real AppSec questions. |
| **High-confidence `in_scope=false` only refuses** | Soft security phrasing is not rejected for missing keywords — obvious junk (weather, jokes) is still rule-refused. |
| **Tool agent off by default** | Fixed operations map to a deterministic pipeline that is easier to test — multi-round tools add latency without improving the required path. |
| **LLM timeout → row-bound templates** | Bounded latency under provider hang — answers stay store-grounded but less fluent. |
| **At most one JSON repair retry** | Caps cost and open-ended loops — may still fall back to a structured template. |
| **`reasoning_effort=none`** | Avoids burning tokens on chain-of-thought — some models may answer slightly thinner. |

### Routing and structure

| Decision | Tradeoff (one line) |
|:---------|:--------------------|
| **Rules for universal syntax** | Severity, CWE, OWASP, paths, count, top-N extracted deterministically — not a full natural-language understanding stack. |
| **Endpoint resolution via scan catalog** | Soft cues map to **ingested** paths (substring / segment) — no Levenshtein-first fuzzy matching that invents wrong routes. |
| **Finding IDs from catalog after load** | Supports arbitrary IDs (`SHIP-AUTH-01`, `web:xss:44`, …) — not limited to `FINDING-\d+` regex alone. |
| **AppSec taxonomy + synonyms** | Domain bridges (IDOR, SSRF, JWT, ATO, …) improve soft class routing — finite coverage, not open-domain NLU. |
| **Explicit user filters beat planner** | User-stated HIGH / endpoint / IDs win over model inference. |
| **RouteResult + QueryPlan + FilterSpec** | Incremental stability (syntax → semantic plan → SQL executor) — avoids a risky mid-project schema rewrite. |
| **Central query orchestrator** | One readable pipeline for a take-home — still modular helpers, not a microservices split. |

### Retrieval and ranking

| Decision | Tradeoff (one line) |
|:---------|:--------------------|
| **BM25 ∪ dense → RRF** | Exact tokens (CWE, paths, parameters) plus paraphrases without fragile score calibration. |
| **Cross-encoder off by default** (`RERANK_MODE=light`) | Fewer models, downloads, and latency — optional CE remains for power users who need it. |
| **Fixed top-k / RRF *k*** | Predictable cost and latency — not adaptive per query. |
| **Hard filters before soft rank when available** | “HIGH on accounts” stays precise — candidates outside the SQL filter never enter context. |
| **Chroma `where` fail-closed** | Broken isolation filters return **no** dense hits — never retry unfiltered and leak another `scan_id`. |
| **BM25 in-process, rebuild on ingest** | Simple multi-scan lexical index — not a distributed search cluster. |
| **Remote embeddings (ModelScope)** | Strong quality without hosting a GPU — ingest/query depend on network and quotas. |

### Generation, citations, safety

| Decision | Tradeoff (one line) |
|:---------|:--------------------|
| **Server citation gate** | Every `findings_referenced` ID must be in the allowed set for this scan — model text cannot invent IDs. |
| **Strip unknown IDs from answer text** | Safer output — may remove a soft mention the model failed to list in the JSON array. |
| **Existence: theoretical risk ≠ reported vuln** | RCE is not inferred from upload/SSRF alone — may under-answer “related risk” unless asked carefully. |
| **Structured templates for inventory** | Generic layouts filled from DB rows — not sample-specific canned essays. |
| **Evidence treated as untrusted** | Blocks prompt-injection via scanner payloads — evidence is explained, never obeyed as instructions. |

### Product and evaluation

| Decision | Tradeoff (one line) |
|:---------|:--------------------|
| **Scan Q&A product boundary** | Clear PTaaS scope — not a general security chatbot or GRC assistant. |
| **Obvious off-topic rules (weather, jokes)** | Free refusal without an extra model call — not a complete open-domain classifier. |
| **`scan_id` isolation** | Correct multi-scan boundaries — wrong/missing id falls back to latest scan. |
| **No multi-tenant auth / audit** | Take-home boundary — not shippable multi-tenant SaaS. |
| **Held-out scan in tests** | Proves non–WealthPilot IDs/endpoints and isolation — still not full industry coverage. |
| **Unit tests with FakeLLM** | Fast offline CI — not a live quality certificate (use `live_validate` for that). |
| **API-only (no frontend)** | Focus on backend correctness — reviewers exercise OpenAPI / curl. |

---

## System overview

<p align="center">
  <img src="docs/assets/architecture-overview.svg" alt="AppSecure architecture overview: Client → FastAPI → Route/Plan → exact FilterEngine or soft Hybrid → Generator → Citation Gate → JSON; SQLite exact inventory; Chroma soft+knowledge; ModelScope embeddings; Cerebras chat" width="900" />
</p>


```mermaid
%%{init: {'theme':'base', 'themeVariables': { 'primaryColor':'#e8f4f8', 'primaryTextColor':'#0f172a', 'primaryBorderColor':'#0d9488', 'lineColor':'#334155', 'secondaryColor':'#f0fdf4', 'tertiaryColor':'#fff7ed'}}}%%
flowchart TB
  subgraph Client
    U[Engineer / PTaaS UI / curl]
  end

  subgraph API["AppSecure FastAPI"]
    EP["/ingest · /query · /health"]
    PIPE[Route → FilterEngine or Hybrid → Generator → Citation gate]
  end

  subgraph Stores
    SQL[(SQLite — findings SoR)]
    CHR[(Chroma — findings + knowledge)]
  end

  subgraph Providers
    EMB[ModelScope embeddings]
    LLM[Cerebras chat LLM]
  end

  U <-->|HTTP JSON| EP
  EP --> PIPE
  PIPE --> SQL
  PIPE --> CHR
  PIPE <--> EMB
  PIPE <--> LLM
```

> [!NOTE]
> **Dual store** — SQLite answers “what is in this scan?” completely. Chroma supports soft language and knowledge context. **Knowledge never proves presence** — only finding rows do.

More diagrams (ingest sequence, hybrid IR, ER model, fail-soft): **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)**.

---

## Query pipeline

```mermaid
%%{init: {'theme':'base', 'themeVariables': { 'primaryColor':'#ecfdf5', 'primaryTextColor':'#064e3b', 'primaryBorderColor':'#059669', 'lineColor':'#475569', 'secondaryColor':'#eff6ff', 'tertiaryColor':'#fef3c7'}}}%%
flowchart TD
  Q[Question + scan_id] --> L[Load scan + catalog]
  L --> R[Rule-based structure]
  R --> EX{Exact structured?}
  EX -->|Yes| F[SQLite FilterEngine]
  F --> T[Structured template]
  T --> G[Citation gate]
  EX -->|No| P[Optional semantic planner]
  P --> V[Validate vs catalog]
  V --> O{High-conf out of scope?}
  O -->|Yes| REF[Refuse]
  O -->|No| H[BM25 ∪ Dense → RRF]
  H --> S{Supporting findings?}
  S -->|No| ABS[Abstain]
  S -->|Yes| K[Knowledge context]
  K --> GEN[Grounded generator or fail-soft template]
  GEN --> G
  G --> RESP[Response]
```

### Hard vs soft questions

```mermaid
flowchart LR
  subgraph Hard["Exact / hard"]
    H1["How many CRITICAL?"]
    H2["Payments endpoint?"]
    H3["Is there RCE?"]
  end
  subgraph Soft["Soft / semantic"]
    S1["Other users' accounts?"]
    S2["SSRF cloud risk?"]
  end
  Hard --> SQL[FilterEngine / existence gate]
  Soft --> HY[Planner? + Hybrid + LLM]
  SQL --> Z["0 LLM typical"]
  HY --> N["1–2 LLM typical"]
```

| Type | Example | Path | Typical LLM calls |
|------|---------|------|------------------:|
| Hard / exact | “How many CRITICAL?” “Top 3?” | FilterEngine / SQL | **0** |
| Existence absent | “Is there RCE?” “command injection?” | Existence + subtype gate → abstain | **0** |
| Soft explain | “SSRF cloud risk?” | Hybrid + generator | **1–2** |
| Soft ambiguous | Unusual phrasing | Planner + hybrid + generator | **2** (≤3 with repair) |

### LLM call budget (defaults)

| Path | Calls |
|------|------:|
| Count / list CRITICAL / A01 / top-N / inventory | **0** |
| Explain/fix with clear structure | **1** (generator) |
| Soft semantic | **2** (planner + generator) |
| Unsupported existence | **0–1** |
| Max normal (optional repair) | **≤3** |

Dedicated **scope LLM** and **tool agent** are **off by default**.

### Latency (target &lt; 10s)

| Path | Typical measured order |
|------|------------------------|
| Count / top‑N / strict filters | **ms – sub-second** |
| List / existence filters | **&lt; 1–2 s** |
| Soft explain / remediate | **often &lt; 2 s**; template if LLM fails soft |
| Live suite p50 / p95 | **~0.5 s / ~1.1 s** (one run — **not an SLA**) |

> [!WARNING]
> Latency is **provider-dependent** (embeddings + chat APIs). Numbers below are **one measured run**, not an SLA. Provider hang → timeout → **store-bound template**, not multi-minute stall.

---

## Anti-hallucination

Layered controls (prompts alone are **not** enough):

```mermaid
flowchart TB
  A[Store as truth] --> B[Existence + subtype gate]
  B --> C[Scan-bound retrieval]
  C --> D[Grounded generator]
  D --> E[Server citation gate]
  E --> F[Fail-closed vectors]
  F --> G[Fail-soft templates]
```

| Control | Behavior |
|---------|----------|
| Store as truth | Only rows in the selected scan can be “found” |
| Existence abstention | No support → `abstained=true`, empty refs |
| **Subtype existence** | “Command injection” needs direct support — SQLi/XSS via parent “injection” is **not** enough |
| Citation gate | `findings_referenced` ⊆ allowed IDs; unknown IDs stripped from text |
| Scan isolation | SQL + vector filters include `scan_id` |
| Fail-closed vectors | Filtered Chroma error → empty hits, never bare unfiltered retry |
| Fail-soft generation | LLM/embed failure → BM25/SQL + templates |
| Knowledge ≠ presence | Playbooks explain verified findings only |

**Specific vs broad existence**

```text
“Is there command injection?”  → strict subtype → abstain if no direct row
“Which injection findings?”    → family listing may return SQLi/XSS/SSRF
“Is there SQL injection?”      → FINDING-001 when present
```

---

## Knowledge base

| Layer | Location | Role |
|-------|----------|------|
| Sample scan | `data/sample_findings.json` | Demo fintech API (`api.wealthpilot.io`) |
| Held-out scan | `data/heldout_scan.json` | Logistics domain + alternate ID schemes |
| OWASP Top 10 2021 | `data/knowledge/owasp_top10_2021/` | Category context + citations |
| CWE definitions | `data/knowledge/cwe/` | Class context for findings in the sample |
| AppSec playbooks | `data/knowledge/appsec_guides/` | BOLA/IDOR, JWT `none`, SSRF, SQLi, auth hardening |

Playbooks improve *how* to explain/fix a **verified** finding. They never prove a finding **exists**.

**Indexing:** each curated markdown file is embedded as **one vector** (one CWE / one OWASP category / one playbook). That matches a compact, already topic-sized corpus and keeps citation IDs stable. Production ingestion of large uploaded PDFs would use heading-aware, token-bounded chunks with stable chunk IDs and source/section metadata — not required for this bundled set.

---

## Quick start

### Prerequisites

| Need | Notes |
|:-----|:------|
| Python **3.11+** | 3.12–3.14 also validated |
| **ModelScope** API token | Embeddings |
| **Cerebras** (or OpenAI-compatible) API key | Chat / planner |

### 1. Configure

```bash
cp .env.example .env
# Set at least:
#   MODELSCOPE_API_KEY=...
#   LLM_API_KEY=...                 # e.g. Cerebras csk-...
#   LLM_BASE_URL=https://api.cerebras.ai/v1
#   LLM_MODEL=gemma-4-31b
```

> [!CAUTION]
> Never commit `.env`. Rotate any key that was pasted into chat or tickets.

### 2. Install & run

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

uvicorn app.main:app --host 0.0.0.0 --port 8000
```

| URL | Purpose |
|:----|:--------|
| http://localhost:8000/docs | OpenAPI interactive docs |
| http://localhost:8000/health | Liveness + model/stack info |

### 3. Ingest + query

```bash
# Ingest sample scan (+ bundled knowledge on first loads)
curl -s http://localhost:8000/ingest \
  -H 'Content-Type: application/json' \
  -d "{\"scan\": $(cat data/sample_findings.json)}" | python -m json.tool

# Inventory question (often 0 LLM)
curl -s http://localhost:8000/query \
  -H 'Content-Type: application/json' \
  -d '{"question":"What are all the critical severity findings?"}' | python -m json.tool

# Held-out scan (different domain / IDs)
curl -s http://localhost:8000/ingest \
  -H 'Content-Type: application/json' \
  -d "{\"scan\": $(cat data/heldout_scan.json)}" | python -m json.tool

curl -s http://localhost:8000/query \
  -H 'Content-Type: application/json' \
  -d '{"question":"How many CRITICAL findings?","scan_id":"scan-heldout-shipyard-2026"}' \
  | python -m json.tool
```

### Demo scripts

| Script | Purpose |
|:-------|:--------|
| `./scripts/demo_queries.sh` | Assignment-style questions |
| `./scripts/hard_queries.sh` | Adversarial / multi-hop |
| `./scripts/live_validate.py` | Automated live suite (server + keys) |

---

## Docker

```bash
cp .env.example .env   # fill MODELSCOPE_API_KEY + LLM_API_KEY
docker compose up --build
curl -s http://localhost:8000/health | python -m json.tool
```

Then use the same ingest/query `curl` examples as above (host port **8000**).

| Compose piece | Behavior |
|---------------|----------|
| Image | Builds from `Dockerfile` (app + knowledge + sample + held-out JSON) |
| Volumes | Persist SQLite + Chroma under named volumes |
| `env_file` | Loads `.env` into the container |

Validated smoke: health, sample ingest, CRITICAL list, held-out count, command-injection abstain — see [`docs/VALIDATION.md`](docs/VALIDATION.md).

---

## API reference

### `POST /ingest`

Accepts a scan payload (and optional reference documents). Upserts SQLite findings, embeds finding narratives, indexes knowledge, rebuilds BM25.

**Request (conceptual):**

```json
{
  "scan": {
    "scan_id": "scan-20260324-001",
    "target": "api.wealthpilot.io",
    "scan_timestamp": "2026-03-24T14:30:00Z",
    "findings": [ { "id": "FINDING-001", "title": "...", "severity": "CRITICAL", "...": "..." } ]
  },
  "reference_documents": []
}
```

**Response:** `scan_id`, `findings_ingested`, `knowledge_chunks`, `status`, `latency_ms`.

### `POST /query`

```json
{
  "question": "How do I fix the SQL injection in transaction search?",
  "scan_id": "scan-20260324-001",
  "top_k_knowledge": 4
}
```

| Field | Meaning |
|-------|---------|
| `answer` | Grounded natural language (markdown-friendly plain text) |
| `citations` | Findings + optional knowledge references |
| `findings_referenced` | **Server-validated** finding IDs only |
| `query_intent` | Routed intent (`list`, `explain`, `remediation`, `existence`, …) |
| `grounded` | Always true for this API (answers constrained to pipeline) |
| `abstained` | `true` when the scan does not support the claim |
| `latency_ms` | Server-side timing |
| `scan_id` | Scan used for the answer |
| `answer_source` | `structured` \| `llm` \| `template` \| `abstain` |
| `model_used` | Chat model id when an LLM produced the answer |

`answer_source=template` means fail-soft after LLM failure — still store-bound, not free invention.

### `GET /health`

Liveness, finding/knowledge counts, embedding model, LLM chain, BM25 size, rerank mode, retrieval stack label.

### `GET /scans/{scan_id}/findings`

List structured findings for debug / explainability.

---

## Configuration

Copy from `.env.example`.

<details>
<summary><strong>Important defaults (click to expand)</strong></summary>

```bash
USE_SEMANTIC_PLANNER=true    # planner for ambiguous NL only
USE_DYNAMIC_SYNTHESIS=true   # LLM explain/remediate from retrieved rows
USE_LLM_SCOPE_GATE=false     # dedicated scope LLM off
USE_TOOL_AGENT=false         # multi-round tools off
RERANK_MODE=light
CROSS_ENCODER_ENABLED=false
LLM_TIMEOUT_S=20
LLM_MAX_RETRIES=0
EMBED_TIMEOUT_S=10
EMBED_MAX_RETRIES=0
```

Storage paths: `DATA_DIR`, `SQLITE_PATH`, `CHROMA_PATH`, `KNOWLEDGE_DIR`.

</details>

---

## Project layout

```text
app/
  main.py            # FastAPI app + lifespan (clients, BM25 warm)
  config.py          # Settings from env
  api/               # routes + Pydantic schemas
  clients/           # embeddings + LLM (timeouts, Fake* for tests)
  db/                # SQLAlchemy models (Scan, Finding)
  ingestion/         # ingest pipeline, knowledge loader
  retrieval/         # SQLite store, FilterEngine, hybrid, BM25, Chroma,
                     # taxonomy, existence_subtype
  rag/               # router, planner, generator, prompts, citations, scope
  services/          # QueryService + citation/pool/tool-agent helpers
data/
  sample_findings.json
  heldout_scan.json
  knowledge/         # owasp_top10_2021, cwe, appsec_guides
tests/               # offline suite (fake embed/LLM)
scripts/             # demo_queries, hard_queries, live_validate
docs/
  ARCHITECTURE.md    # full design (this is the deep dive)
  VALIDATION.md      # measured offline/live/Docker evidence
study-guide/         # interactive HTML study guide (open via http.server)
Dockerfile
docker-compose.yml
requirements.txt
.env.example
```

---

## Tests and measured evidence

### Offline (no network)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

Also validated with a **clean** venv install.

Coverage includes: severity/OWASP/precision operators; citation gate; RCE/command-injection abstain; fail-closed vector isolation; held-out IDs; planner merge; fail-soft timeouts; golden cases; API smoke.

### Live (server + real keys)

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
# ingest sample first
.venv/bin/python scripts/live_validate.py
```

### Measured evidence (one environment — **not an SLA**)

| Metric | Result |
|:-------|:-------|
| Offline suite | **148 passed** |
| Live correctness | **43 / 43** |
| README + Docker smoke | **OK** |
| Latency p50 | **~0.4–0.6 s** |
| Latency p95 | **~1.0–1.1 s** |

> [!NOTE]
> Some soft answers use **`answer_source=template`** when the chat model times out or returns invalid JSON. That is intentional **fail-soft** with store-bound citations — not free invention.

Full commands, paraphrase notes, Docker log: **[`docs/VALIDATION.md`](docs/VALIDATION.md)**.

---

## Sample questions

Assignment-style (sample scan):

1. What are all the critical severity findings?  
2. Explain the IDOR vulnerability on the accounts endpoint.  
3. How do I fix the SQL injection in transaction search?  
4. Which findings are related to OWASP A01 Broken Access Control?  
5. Is there a remote code execution vulnerability?  
6. What authentication issues were found?  
7. Give me a summary of all findings sorted by severity.  
8. What's the risk of the SSRF finding and how could an attacker exploit it?  
9. Are there any findings related to the payments endpoint?  
10. Compare the two IDOR findings — are they the same root cause?  

Useful demos of controls:

- “Are there any **command injection** findings?” → **abstain** (not SQLi/XSS)  
- Held-out: “How many CRITICAL findings?” with `scan_id=scan-heldout-shipyard-2026`  
- Held-out IDs: `SHIP-AUTH-01`, `web:xss:44`, `VULN_2026_91`

---

## Evaluation approach

Evaluation emphasizes **held-out evidence**, not sample memorization:

1. **Sample scan** — assignment-shaped demo (`FINDING-00N`).  
2. **Held-out scan** — logistics domain; IDs like `SHIP-AUTH-01`, `web:xss:44`, `VULN_2026_91`.  
3. **Isolation** — multi-scan queries must not leak IDs across `scan_id`.  
4. **Abstention** — unsupported existence and unknown endpoints refuse to invent.  
5. **No answer packs** — templates bind to store rows; no hardcoded held-out prose.  
6. **Subtype existence** — specific vulns require direct support, not parent-family OR matches.

---

## Known limitations

| Area | Limitation |
|:-----|:-----------|
| Soft NL | Not full NLU — unusual paraphrases can mis-route or abstain |
| Providers | Latency / quotas vary; inventory stays local/SQL; embeds/LLM are remote |
| Taxonomy | Curated domain knowledge — not live MITRE/OWASP sync |
| Knowledge indexing | Whole-doc vectors for a compact corpus — large uploads need chunking (see [Design tradeoffs](#design-tradeoffs)) |
| Vector layout | One Chroma collection + metadata filters — not separate physical indexes |
| Endpoint soft match | Catalog substring/segment match — not Levenshtein/embedding endpoint NLU |
| Rerank | Cross-encoder off by default — RRF only unless you enable CE |
| Orchestrator | Modular helpers, still one main query service |
| Product scope | No multi-tenant auth / audit; API-only (no UI) |
| Knowledge role | Playbooks explain findings; they do **not** invent presence |
| Observability | Single `latency_ms` — not full stage-level metrics export |

**Roadmap ideas:** heading-aware knowledge chunks for large refs, separate findings/knowledge collections if scale demands it, broader multi-scan eval + CI latency budgets, stage-level observability, optional multi-tenant productization.

---

## Security notes

> [!CAUTION]
> Treat scanner **evidence** fields as **untrusted** in prompts. Never commit `.env` or paste live keys into tickets.

- Citation IDs are validated against retrieved/filtered findings for the **selected scan** only.  
- Chroma filtered queries **fail closed** — a broken `where` returns no hits, never unfiltered results.

---

## Further reading

| Document | Contents |
|----------|----------|
| **[`study-guide/`](study-guide/)** | **Interactive study guide** (diagrams, quizzes, command cookbook) — `cd study-guide && python -m http.server 5500` |
| **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)** | Full architecture: context diagram, dual store, ingest/query sequences, hybrid IR, planner policy, citation gate, package map, failures, tradeoffs |
| **[`docs/VALIDATION.md`](docs/VALIDATION.md)** | Clean venv, live suite, Docker smoke, paraphrase notes, limitations |

---

## License / assignment

Take-home implementation for **AppSecure** (PTaaS). Datasets are fictional. OWASP/CWE materials include pointers for citation. **README + ARCHITECTURE.md** describe the shipped system; **VALIDATION.md** records how it was tested.
