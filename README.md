# Vulnerability Explainer RAG Agent (AppSecure)

RAG-backed FastAPI service for **natural-language Q&A over application security scan results** — with **citations**, **hybrid retrieval**, and **hard anti-hallucination controls**.

Think of this as the backend for *“talk to your scan results”* in a PTaaS dashboard: list, explain, remediate, and abstain when the scan does not support the claim.

| | |
|---|---|
| **API** | FastAPI (`/ingest`, `/query`, `/health`) |
| **Findings store** | SQLite — **system of record** |
| **Vector store** | Chroma (persistent) |
| **Embeddings** | `Qwen/Qwen3-Embedding-8B` via ModelScope |
| **LLM** | **Cerebras** `gemma-4-31b` (OpenAI-compatible) |
| **Retrieval** | SQL filters + **BM25 + dense + RRF + MiniLM cross-encoder** |
| **Knowledge** | OWASP Top 10 2021 + CWEs in the sample + AppSec playbooks |

---

## Architecture

Scanner findings are **authoritative structured records**. Pure top‑k vector RAG over JSON fails on full inventory, existence checks, and stable citations. This system uses a **dual store**:

```text
Question
   │
   ▼
┌──────────────────────────────────────────┐
│ Route / plan                             │
│  rules (operators) + optional semantic   │
│  planner (LLM → FilterSpec JSON)         │
│  fallback: rule_based_route              │
└──────────────────┬───────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────┐
│ FilterEngine (SQLite findings)           │
│  count / top_n / severity / CWE /        │
│  endpoint / topics / include|exclude     │
└──────────────────┬───────────────────────┘
                   │
     empty + existence? ──► abstain (no invent)
                   │
                   ▼
┌──────────────────────────────────────────┐
│ Soft retrieval (when needed)             │
│  BM25 ∪ dense → RRF → cross-encoder      │
│  + knowledge vectors (CWE/OWASP/guides)│
└──────────────────┬───────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────┐
│ Answer                                   │
│  inventory → structured templates        │
│  explain/remediate → grounded LLM        │
│  citation gate (IDs ⊆ retrieved only)    │
└──────────────────────────────────────────┘
```

**Principle:** the LLM **proposes** filters and **narrates** answers; the **store decides which findings exist**. Citations are validated server-side.

### Why not “agent-only” or “embed-only”?

| Approach | Failure mode on this problem |
|----------|------------------------------|
| Embed JSON + chat | Misses full CRITICAL list; invents vulns |
| LLM free-form inventory | “15 CRITICAL” when there are 2 |
| SQL only | Weak on soft phrasing (“other users’ profiles”) |
| **This hybrid** | Exact ops from SQL; soft questions via hybrid IR + LLM |

---

## Knowledge base

| Layer | Location | Role |
|-------|----------|------|
| Scan findings | `data/sample_findings.json` | What was found (truth) |
| OWASP Top 10 2021 | `data/knowledge/owasp_top10_2021/` | Assignment + citations |
| CWE definitions | `data/knowledge/cwe/` | Assignment + citations |
| AppSec playbooks *(extra)* | `data/knowledge/appsec_guides/` | BOLA/IDOR, JWT `none`, SSRF/metadata, SQLi, auth hardening, scanner interpretation |

Playbooks are intentional product depth (how a PTaaS engineer answers), not random PDF dumps. Knowledge is **offline curated** for deterministic demos; production would sync OWASP/MITRE on a schedule.

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

Useful knobs:

```bash
USE_SEMANTIC_PLANNER=true    # LLM FilterSpec for soft NL (skipped when rules are confident)
USE_DYNAMIC_SYNTHESIS=true   # LLM explain/remediate from retrieved rows
USE_TOOL_AGENT=false         # multi-round tools off by default (latency)
LLM_MAX_TOKENS=1200
RERANK_MODE=auto             # auto | cross_encoder | light
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

Response fields:

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

1. **Route** — rule operators (count, top‑N, severity, CWE, endpoint, topics) + optional **semantic planner** (LLM → structured plan, merged with rules)  
2. **FilterEngine** — set algebra on SQLite inventory (never invents rows)  
3. **Abstain** — empty existence / unknown path → fixed refusal  
4. **Hybrid IR** (soft free-text) — BM25 ∪ dense → RRF → MiniLM CE (or light fallback)  
5. **Generate** — structured templates for inventory; grounded LLM for explain/remediate/compare  
6. **Citation gate** — strip unknown `FINDING-*` IDs from refs and answer text  

Layered defense: **prompts alone are not a control**.

### Hard vs soft questions

| Type | Example | Path |
|------|---------|------|
| Hard / exact | “How many CRITICAL?” “Top 3?” “Payments endpoint?” | SQL / FilterEngine (often **no LLM**) |
| Soft / fuzzy | “Other users’ accounts?” “SSRF cloud risk?” | Hybrid retrieval + LLM on retrieved rows |

---

## Design decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Findings storage | SQLite | Exact filters, re-ingest, zero infra |
| Vectors | Chroma | Zero-ops for take-home; metadata filters |
| Embeddings | Qwen3-Embedding-8B (ModelScope) | Strong general embedder; OpenAI-compatible API |
| LLM | Cerebras `gemma-4-31b` | High throughput for plan/answer under latency budget |
| Free-text IR | BM25 + dense + RRF + CE | Lexical exactness + semantic paraphrases |
| Orchestration | Filter-first hybrid | Inventory truth; LLM for narration |
| Tools agent | Off by default | Latency; optional deep mode later |

### Latency (target &lt; 10s)

Typical profile with Cerebras Gemma 4 (local measurement, single user):

| Path | Observed order |
|------|----------------|
| Count / top‑N / strict filters | **milliseconds** |
| Many list / existence filters | **&lt; 1–2 s** |
| LLM explain / soft synthesis | **usually a few seconds**; depends on provider load |

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
  services/      # query orchestrator
data/
  sample_findings.json
  knowledge/owasp_top10_2021/
  knowledge/cwe/
  knowledge/appsec_guides/
tests/
scripts/
  demo_queries.sh
  hard_queries.sh
  live_validate.py
```

---

## Tests

Unit tests use **fake embeddings + fake LLM** (no network):

```bash
pytest -q
```

Live validation (server running + real keys):

```bash
.venv/bin/python scripts/live_validate.py
```

Coverage includes: severity/OWASP filters, RCE abstain, citation stripping, precision operators (count, top‑N, endpoint, secrets), golden hard cases, API smoke.

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

## Known limitations & future work

1. **Soft NL is not full NLU** — planner + rules + taxonomy; unusual phrasing can still mis-route.  
2. **Single-scan demo** — sample overfit risk; add more fixtures for production confidence.  
3. **Provider latency / quotas** — free tiers vary; inventory stays local/SQL.  
4. **Taxonomy is curated domain knowledge** — not live MITRE/OWASP sync; no finding-ID answer packs.  
5. **Orchestrator still thick** — further split into plan → filter → retrieve → generate → gate modules.  
6. **No multi-tenant auth / audit** — out of take-home scope.  
7. **Cross-encoder download** — first CE use may fetch MiniLM; use `RERANK_MODE=light` in CI.  

**Next upgrades (roadmap):** stronger LLM FilterSpec planner eval suite, dual-scan golden, stage-level latency metrics, optional multi-tenant.

---

## Security notes

- Treat scanner evidence fields as **untrusted** in prompts.  
- Never commit `.env` or paste live keys into tickets.  
- Citation IDs are validated against retrieved findings only.

---

## License / assignment

Take-home implementation for **AppSecure** (PTaaS). Dataset is fictional (`api.wealthpilot.io`). OWASP/CWE summaries include official links for citation. Design history: earlier notes in session plans; **this README is authoritative for the shipped system**.
