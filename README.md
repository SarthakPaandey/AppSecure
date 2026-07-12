# Vulnerability Explainer RAG Agent (AppSecure)

RAG-backed FastAPI service for **natural-language Q&A over application security scan results** — with **citations**, **hybrid retrieval**, and **hard anti-hallucination controls**.

**Structured findings decide what exists. Hybrid retrieval resolves soft language. The LLM explains only verified findings.**

| | |
|---|---|
| **API** | FastAPI (`/ingest`, `/query`, `/health`) |
| **Findings store** | SQLite — **system of record** |
| **Vector store** | Chroma (persistent), **fail-closed** metadata filters |
| **Embeddings** | `Qwen/Qwen3-Embedding-8B` via ModelScope |
| **LLM** | **Cerebras** `gemma-4-31b` (OpenAI-compatible) |
| **Retrieval** | SQL filters + **BM25 ∪ dense → RRF** (cross-encoder optional, off by default) |
| **Knowledge** | OWASP Top 10 2021 + CWEs + AppSec playbooks |

---

## Architecture

Scanner findings are **authoritative structured records**. Pure top‑k vector RAG over JSON fails on full inventory, existence checks, and stable citations. This system uses a dual store and a constrained pipeline:

```text
Question + scan_id
  → Load selected scan + catalog
  → Extract explicit structure
  → Exact structured?
       Yes → SQLite FilterEngine → Structured template → Citation gate
       No  → Optional semantic planner (ambiguous only)
              → Validate against catalog
              → High-confidence out of scope?
                   Yes → Product-boundary refusal
                   No  → BM25 + Dense → RRF
                        → Verify selected-scan membership
                        → Supporting findings?
                             No  → Grounded abstention
                             Yes → Knowledge (CWE/OWASP, fail-closed filters)
                                  → Grounded generator (or row-bound fallback)
                                  → Citation gate
  → Response
```

**Principle:** the LLM **proposes** filters (planner, ambiguous only) and **narrates** answers (generator); the **store decides which findings exist**. Citations are validated server-side.

### LLM call budget (defaults)

| Path | Calls |
|------|------:|
| Count / list CRITICAL / A01 / top-N / inventory | **0** |
| Explain/fix with clear rules | **1** (generator only) |
| Soft semantic | **2** (planner + generator) |
| Unsupported existence | **0–1** |
| Max normal (with one repair) | **≤3** |

Dedicated scope LLM and multi-round tool agent are **off by default** (optional via env).

### Why SQLite + RAG?

| Approach | Failure mode on this problem |
|----------|------------------------------|
| Embed JSON + chat | Misses full CRITICAL list; invents vulns |
| LLM free-form inventory | “15 CRITICAL” when there are 2 |
| SQL only | Weak on soft phrasing (“other users’ profiles”) |
| **This hybrid** | Exact ops from SQL; soft questions via hybrid IR + grounded LLM |

---

## Knowledge base

| Layer | Location | Role |
|-------|----------|------|
| Sample scan | `data/sample_findings.json` | Demo domain (`api.wealthpilot.io`) |
| Held-out scan | `data/heldout_scan.json` | Different domain + ID schemes (evaluation) |
| OWASP Top 10 2021 | `data/knowledge/owasp_top10_2021/` | Category context + citations |
| CWE definitions | `data/knowledge/cwe/` | Vulnerability class context |
| AppSec playbooks | `data/knowledge/appsec_guides/` | BOLA/IDOR, JWT `none`, SSRF, SQLi, auth |

Playbooks deepen *how* to explain/fix a verified finding. They never prove a finding **exists** — only scan rows do.

---

## Quick start

### Prerequisites

- Python 3.11+
- **ModelScope** API token (embeddings)
- **Cerebras** API key (chat / planner) — or any OpenAI-compatible LLM

### Configure

```bash
cp .env.example .env
# Set at least:
#   MODELSCOPE_API_KEY=...
#   LLM_API_KEY=...              # Cerebras csk-...
#   LLM_BASE_URL=https://api.cerebras.ai/v1
#   LLM_MODEL=gemma-4-31b
```

Never commit `.env`. Rotate any key that was pasted into chat or tickets.

Useful knobs (defaults match `.env.example`):

```bash
USE_SEMANTIC_PLANNER=true    # planner for ambiguous NL only
USE_DYNAMIC_SYNTHESIS=true   # LLM explain/remediate from retrieved rows
USE_LLM_SCOPE_GATE=false     # dedicated scope LLM off (rules + planner in_scope)
USE_TOOL_AGENT=false         # multi-round tools off (not the main path)
RERANK_MODE=light            # RRF + light lexical; CE optional
CROSS_ENCODER_ENABLED=false
```

### Install & run

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

uvicorn app.main:app --host 0.0.0.0 --port 8000
```

- OpenAPI: http://localhost:8000/docs  
- Health: http://localhost:8000/health  

### Docker

```bash
cp .env.example .env   # fill keys
docker compose up --build
```

### Ingest + query

```bash
# Ingest sample scan (+ bundled knowledge)
curl -s http://localhost:8000/ingest \
  -H 'Content-Type: application/json' \
  -d "{\"scan\": $(cat data/sample_findings.json)}" | python -m json.tool

# Query
curl -s http://localhost:8000/query \
  -H 'Content-Type: application/json' \
  -d '{"question":"What are all the critical severity findings?"}' | python -m json.tool

# Held-out scan (different domain / ID schemes)
curl -s http://localhost:8000/ingest \
  -H 'Content-Type: application/json' \
  -d "{\"scan\": $(cat data/heldout_scan.json)}" | python -m json.tool

curl -s http://localhost:8000/query \
  -H 'Content-Type: application/json' \
  -d '{"question":"How many CRITICAL findings?","scan_id":"scan-heldout-shipyard-2026"}' \
  | python -m json.tool
```

Demos:

```bash
./scripts/demo_queries.sh      # assignment-style sample questions
./scripts/hard_queries.sh      # adversarial / multi-hop
./scripts/live_validate.py     # automated live suite (server + keys)
```

---

## API

### `POST /ingest`

Upserts the structured findings store, embeds finding narratives, indexes OWASP/CWE/playbooks.

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
| `answer` | Grounded natural language |
| `citations` | Findings + knowledge references |
| `findings_referenced` | **Server-validated** finding IDs only |
| `query_intent` | Routed intent |
| `abstained` | `true` when the scan does not support the claim |
| `latency_ms` | Server-side timing |
| `answer_source` | `structured` \| `llm` \| `template` \| `abstain` |
| `model_used` | Chat model id when an LLM produced the answer |

### `GET /health`

Liveness, finding/knowledge counts, embedding model, LLM chain, retrieval stack.

### `GET /scans/{scan_id}/findings`

List structured findings (debug / explainability).

---

## Query path (anti-hallucination)

1. **Load scan + catalog** — finding IDs and endpoints from the selected scan  
2. **Structural parse** — severity, CWE, OWASP, paths, operators; **catalog-aware IDs** (`FINDING-001`, `SHIP-AUTH-01`, `web:xss:44`, …)  
3. **Exact path** — FilterEngine on SQLite inventory → template (often **0 LLM**)  
4. **Optional planner** — ambiguous NL only; validates against catalog; high-conf `in_scope=false` refuses; malformed/low-conf **fail open** to retrieval  
5. **Hybrid IR** — BM25 ∪ dense → RRF; vector filters **fail closed** (never drop `scan_id`)  
6. **Generate** — inventory templates; grounded LLM for explain/remediate/compare  
7. **Citation gate** — strip unknown IDs; existence requires a scan row (playbooks ≠ findings)  

Layered defense: **prompts alone are not a control**.

### Hard vs soft questions

| Type | Example | Path |
|------|---------|------|
| Hard / exact | “How many CRITICAL?” “Top 3?” “Payments endpoint?” | SQL / FilterEngine (often **no LLM**) |
| Soft / fuzzy | “Other users’ accounts?” “SSRF cloud risk?” | Planner (optional) + hybrid + LLM on rows |

---

## Design decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Findings storage | SQLite | Exact filters, re-ingest, zero infra |
| Vectors | Chroma + fail-closed `where` | Isolation; never bare-retry filters |
| Embeddings | Qwen3-Embedding-8B (ModelScope) | Strong general embedder |
| LLM | Cerebras `gemma-4-31b` | Plan + narrate under latency budget |
| Free-text IR | BM25 + dense + RRF | Lexical + semantic; CE optional |
| Orchestration | Filter-first hybrid | Inventory truth; LLM for narration |
| Scope | Rules + planner `in_scope` | No required dedicated scope LLM |
| Tools agent | Off by default | Latency; optional deep mode |

### Latency (target &lt; 10s)

| Path | Observed order |
|------|----------------|
| Count / top‑N / strict filters | **milliseconds** |
| Many list / existence filters | **&lt; 1–2 s** |
| LLM explain / soft synthesis | **usually a few seconds**; depends on provider |

Inventory does **not** need the LLM. Soft paths use at most planner + answer (planner skipped when rules are already confident).

---

## Project layout

```text
app/
  api/           # routes + schemas
  clients/       # embeddings + LLM (OpenAI-compatible)
  db/            # SQLAlchemy models
  ingestion/     # pipeline, knowledge loader
  retrieval/     # findings store, filter_engine, taxonomy, hybrid, BM25, CE
  rag/           # planner, prompts, router, generator, citations, tools
  services/      # query orchestrator (essay pipeline helpers)
data/
  sample_findings.json
  heldout_scan.json
  knowledge/...
tests/
scripts/
docs/
  plan-v0.md
  STUDY_GUIDE_AND_JUSTIFICATION.md
```

---

## Tests

Unit tests use **fake embeddings + fake LLM** (no network):

```bash
pytest -q
```

Coverage includes:

- Severity / OWASP / precision operators (count, top‑N, endpoint)
- Citation gate + RCE/unsupported existence abstain  
- Vector filter **fail-closed** isolation  
- **Held-out scan** (different domain, arbitrary IDs, multi-scan isolation)  
- Planner merge / catalog validation / `in_scope` policy  
- Golden hard cases and API smoke  

Live validation (server running + real keys):

```bash
.venv/bin/python scripts/live_validate.py
```

---

## Sample questions (assignment)

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

---

## Tradeoffs and evaluation approach

Evaluation emphasizes **held-out evidence**, not sample memorization:

1. **Sample scan** — assignment-shaped demo (`FINDING-00N`).  
2. **Held-out scan** — logistics domain with IDs like `SHIP-AUTH-01`, `web:xss:44`, `VULN_2026_91`.  
3. **Isolation** — multi-scan queries never leak finding IDs across `scan_id`.  
4. **Abstention** — unsupported existence and unknown endpoints refuse to invent.  
5. **No answer packs** — generator templates bind to store rows; no hardcoded held-out prose.

Design is **surgical**: adapters and helpers over a full rewrite of `RouteResult` / `QueryPlan` / `FilterSpec`.

---

## Known limitations

1. **Soft NL is not full NLU** — planner + rules + taxonomy; unusual phrasing can still mis-route.  
2. **Provider latency / quotas** — free tiers vary; inventory stays local/SQL.  
3. **Taxonomy is curated** — not live MITRE/OWASP sync.  
4. **Orchestrator still relatively thick** — stages are helpers; further module splits possible.  
5. **No multi-tenant auth / audit** — out of take-home scope.  
6. **Cross-encoder optional** — enable via `CROSS_ENCODER_ENABLED=true` + `RERANK_MODE=cross_encoder` if needed.  
7. **Knowledge guides ≠ findings** — playbooks explain verified rows; they do not invent presence.

**Roadmap ideas:** stronger planner eval suite, stage-level latency metrics, optional multi-tenant.

---

## Security notes

- Treat scanner evidence fields as **untrusted** in prompts.  
- Never commit `.env` or paste live keys into tickets.  
- Citation IDs are validated against retrieved findings only.  
- Chroma filtered queries **fail closed** — a broken `where` returns no hits, never unfiltered results.

---

## Study guide / design defense

For architecture justification, tradeoffs, evaluation approach, what’s missing, and viva Q&A, see:

**[`docs/STUDY_GUIDE_AND_JUSTIFICATION.md`](docs/STUDY_GUIDE_AND_JUSTIFICATION.md)**

---

## License / assignment

Take-home implementation for **AppSecure** (PTaaS). Datasets are fictional. OWASP/CWE summaries include official links for citation. **This README is authoritative for the shipped system.**
