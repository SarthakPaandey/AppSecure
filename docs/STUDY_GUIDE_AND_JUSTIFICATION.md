# AppSecure Vulnerability Explainer RAG  
## Study Guide, Architecture Justification & Honest Defense Notes

**Purpose of this document**  
Use this before a review / viva / submission write-up. It explains **what we built**, **why we built it that way**, **what is still hardcoded**, **tradeoffs**, **what we are missing**, **how many LLM calls we make**, and **how to answer “did you game the sample?”**

**Audience**  
You (author) + a technical reviewer who may be skeptical of regex, templates, and sample-tuned tests.

**Product one-liner**  
A FastAPI service that answers natural-language questions **over ingested application-security scan findings**, with **citations**, **hybrid retrieval**, **LLM scope gating (Gemma)**, and **hard anti-hallucination controls**. Demo dataset is a fictional fintech API; the **engine is scan-schema-general**, not fintech-product-locked.

**Repo alignment**  
Reflects post-generalization + scope-gate work (catalog endpoints, pattern playbooks, row-bound templates, Gemma scope relatedness). Re-read `app/rag/scope.py` and `app/services/query_service.py` if the code has moved further.

---

# Table of contents

1. [Elevator pitch & problem](#1-elevator-pitch--problem)  
2. [What success looks like for this assignment](#2-what-success-looks-like-for-this-assignment)  
3. [End-to-end architecture](#3-end-to-end-architecture)  
4. [Why not pure RAG / pure agent / pure SQL](#4-why-not-pure-rag--pure-agent--pure-sql)  
5. [Data model & dual store](#5-data-model--dual-store)  
6. [Request lifecycle (query path)](#6-request-lifecycle-query-path)  
7. [LLM call budget (how many calls?)](#7-llm-call-budget-how-many-calls)  
8. [Scope gate (Gemma relatedness)](#8-scope-gate-gemma-relatedness)  
9. [Module-by-module justification](#9-module-by-module-justification)  
10. [Key functions & design contracts](#10-key-functions--design-contracts)  
11. [Models, providers, config](#11-models-providers-config)  
12. [What is still “hardcoded” (honest inventory)](#12-what-is-still-hardcoded-honest-inventory)  
13. [Tradeoffs matrix](#13-tradeoffs-matrix)  
14. [“Did you game the take-home?” defense](#14-did-you-game-the-take-home-defense)  
15. [What we are still missing](#15-what-we-are-still-missing)  
16. [Healthcare / logistics / non-fintech](#16-healthcare--logistics--non-fintech)  
17. [How to demo & what to say live](#17-how-to-demo--what-to-say-live)  
18. [Likely reviewer questions (Q&A)](#18-likely-reviewer-questions-qa)  
19. [File map (study checklist)](#19-file-map-study-checklist)  
20. [Glossary](#20-glossary)

---

# 1. Elevator pitch & problem

### Problem
PTaaS / AppSec platforms produce **structured scanner findings** (severity, CWE, endpoint, evidence, remediation). Users want to ask:

- “What are all CRITICAL findings?”  
- “Explain the IDOR on accounts.”  
- “How do I fix the SQLi?”  
- “Is there RCE?”  
- “Compare the two IDORs.”  
- Soft: “Could someone access other users’ data?”

### Naive approaches fail

| Approach | Typical failure |
|----------|-----------------|
| Stuff JSON into a prompt | Misses full inventory; invents IDs; unstable |
| Embed findings + chat only | Soft match; wrong top‑k; incomplete lists |
| Free-form LLM “count CRITICAL” | Hallucinates counts (“15 CRITICAL” when there are 2) |
| SQL only | Weak on soft phrasing (“other users’ profiles”) |
| Agent with tools only | Latency; tool loops; still invents if not gated |
| Keyword-only “off-topic” filter | Misses soft AppSec; false positives/negatives |

### Our approach (one sentence)

**Store decides which findings exist; hybrid IR retrieves soft matches; Gemma (optional) gates product scope and plans/narrates; server-side citation gate enforces that every `FINDING-*` ID was actually retrieved.**

---

# 2. What success looks like for this assignment

| Requirement | How we address it |
|-------------|-------------------|
| Ingest scan + knowledge | `POST /ingest` → SQLite + Chroma + BM25 |
| Natural language Q&A | `POST /query` |
| Citations | Findings + knowledge refs; IDs validated |
| Anti-hallucination | Empty existence → abstain; citation gate; scope refuse off-topic |
| Sample questions | Demos + `scripts/live_validate.py` |
| Extensible knowledge | OWASP/CWE + **pattern** playbooks + optional `reference_documents` |
| Not open-domain chat | Scope gate (rules + Gemma relatedness) |

**Submission-ready means:** coherent design, demo works, tests pass, limitations honest—not “production multi-tenant GRC.”

---

# 3. End-to-end architecture

```text
                    ┌─────────────────────┐
                    │  Client / reviewer  │
                    └─────────┬───────────┘
                              │ HTTP
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         POST /ingest    POST /query     GET /health
              │               │
              ▼               ▼
     IngestionPipeline   QueryService
              │               │
     ┌────────┴────────┐     │
     ▼                 ▼     │
 FindingsStore     VectorStore
  (SQLite)          (Chroma)
     │                 │
     └────────┬────────┘
              │
     BM25Index (in-process)
              │
     ┌────────┴────────┐
     │  Scope gate     │  rules (structural / obvious junk)
     │  + Gemma JSON   │  related?  (soft questions)
     └────────┬────────┘
              │ related
     Router rules + optional SemanticPlanner
              │
     FilterEngine (precision)  OR  HybridRetriever (soft)
              │
     AnswerGenerator (structured / LLM / template)
              │
     Citation gate
              ▼
         QueryResponse
```

### Design principle (memorize this)

> **LLM proposes; store disposes.**  
> The model may gate scope, suggest filters, and write prose. It may **not** invent finding IDs, severities, or endpoints that are not in retrieved context.

### Generalization principle

> **No finding-ID answer packs. No fixed product paths as the only truth.**  
> Endpoints come from the **ingested catalog**. Templates bind **row fields**. Playbooks are **vuln patterns**, not WealthPilot-only docs.

---

# 4. Why not pure RAG / pure agent / pure SQL

| Approach | Failure mode | Our fix |
|----------|--------------|---------|
| Vectors only | Incomplete CRITICAL list | SQLite FilterEngine for inventory |
| LLM counts | Hallucinated N | Count from filtered set only |
| SQL only | Soft NL weak | Hybrid BM25+dense+RRF+CE + planner |
| Tools-only agent | Latency; invent | Tools **off by default** |
| Keyword scope only | Soft AppSec false refuse | **Gemma relatedness** for soft questions |

---

# 5. Data model & dual store

### Ingest contract (N-agnostic)

Same schema as assignment JSON — **not limited to 15 findings**:

```text
scan_id, target, scan_timestamp
findings[]: id, title, severity, cwe_id, owasp_category,
            endpoint, method, parameter, description,
            evidence, remediation_hint
```

A reviewer can ingest healthcare/logistics scans of this **shape** with any count.

### Stores

| Store | Role |
|-------|------|
| **SQLite** (`FindingsStore`) | System of record; filters; `distinct_endpoints` catalog |
| **Chroma** | Soft retrieval + knowledge vectors |
| **BM25** | Lexical exactness over finding text |
| **Knowledge dir** | OWASP Top 10, CWEs, pattern playbooks |

Playbooks under `data/knowledge/appsec_guides/` explain **patterns** (SSRF classes, JWT none, BOLA, SQLi, auth hardening)—not fixed sample parameters as the only truth. Instance endpoint/parameter come from the **finding row** at answer time.

---

# 6. Request lifecycle (query path)

Primary orchestrator: `QueryService.query()` in `app/services/query_service.py`.

### Stage 0 — Empty store
If no findings ingested → fixed message: call `POST /ingest` first. **0 LLM.**

### Stage A — Rules + catalog endpoints
1. `rule_based_route(question)` — operators (severity, CWE, count, top_n, topics, path-param, intent cues).  
2. `resolve_soft_endpoints(question, distinct_endpoints)` — map “X endpoint” / “Y page” to **live catalog** (substring / last segment; **not** Levenshtein-first).

### Stage B — Scope gate (`app/rag/scope.py`)
Decide if the question is **about this scan** vs off-topic chat.

1. **Structural slots** (severity, CWE, FINDING-id, count, path-param, explicit `/api/...`) → **in scope**, no LLM.  
2. **Obvious junk** (weather, joke, recipe, …) → **out of scope**, no LLM.  
3. **Else** → **Gemma** (`USE_LLM_SCOPE_GATE=true`): JSON `{"related": true|false, ...}`.  
4. LLM error → **fail-open** (`related=true`) so we don’t false-refuse scan questions.

Out of scope → fixed refusal, `abstained=true`. **Stops before planner/answer.**

### Stage C — Optional semantic planner
If rules not “confident” and planner enabled → LLM FilterSpec-like plan, merged with rules; endpoints resolved against catalog.

### Stage D — Precision vs soft retrieval

| Path | When | Mechanism |
|------|------|-----------|
| **Precision** | count, top_n, severity lists, topics/phrases, path_param, strict endpoints | `FilterEngine.apply_filters` on **full inventory** |
| **Soft** | explain / free text / hybrid | BM25 ∪ dense → RRF → optional cross-encoder + knowledge |

Empty existence → **abstain** (no invent).

### Stage E — Generate

| Intent family | Path |
|---------------|------|
| list / summary / count / existence (yes set) | Structured templates from store |
| explain / remediation / compare | LLM JSON if `USE_DYNAMIC_SYNTHESIS` |
| LLM fail | **Row-bound** `_template_explain` / `_template_compare` (endpoint, param, description, remediation_hint from rows) |

**Removed (generalization):** `_template_ssrf_cloud`, `_template_auth_triad_compare` (demo-specific prose).

### Stage F — Citation gate
`findings_referenced ⊆ retrieved IDs`; strip hallucinated IDs from answer when possible.

### Response fields
`answer`, `citations`, `findings_referenced`, `query_intent`, `abstained`, `latency_ms`, `answer_source` (`structured` \| `llm` \| `template` \| `abstain`), `model_used`.

---

# 7. LLM call budget (how many calls?)

**Defaults:**  
`USE_LLM_SCOPE_GATE=true`, `USE_SEMANTIC_PLANNER=true`, `USE_DYNAMIC_SYNTHESIS=true`, `USE_TOOL_AGENT=false`.

Chat model is typically **Cerebras `gemma-4-31b`** (OpenAI-compatible). Embeddings are a **separate** API (not counted as “chat LLM calls” below).

### Call sources (chat only)

| Stage | Max calls | Typical |
|-------|-----------|---------|
| Scope gate | 1 | 0 if structural / obvious junk |
| Semantic planner | 1 | 0 if rules confident |
| Answer synthesis | 1 | 0 if structured inventory path |
| Answer JSON repair | 1 | 0 if first parse OK |
| Tool agent | up to `TOOL_AGENT_MAX_ROUNDS` (~3) | **0** (off by default) |

**Not on main path:** `QueryRouter` LLM classify — production path uses `rule_based_route` only.

### Examples

| Question type | Typical chat LLM calls |
|---------------|------------------------|
| “All CRITICAL findings?” | **0** |
| “How many HIGH?” | **0** |
| “Is there RCE?” (rules existence) | **0** |
| “What’s the weather?” | **0** (rules out) |
| Soft AppSec (“other users’ accounts?”) | **2–3** (scope + optional plan + answer) |
| “How do I fix the SQLi…?” | **1–2** |
| Soft + plan + answer + repair | **≤ 4** |

### Scope gate `max_tokens`

Scope JSON is tiny (`related`, `confidence`, `reason`). Implementation uses a **small max_tokens** (conservative, e.g. ~80) because output is short; if parse fails we **fail-open**. Raising to ~120–150 is optional safety, not required for correctness of the design.

### Takeaway for viva

> Hard inventory is free (0 chat LLM). Soft explain is usually 2–3 Gemma calls, not a long agent loop. Scope is one small JSON call when needed.

---

# 8. Scope gate (Gemma relatedness)

### Why not keywords only?

Keywords cannot reliably tell:

- “Could someone access other users’ account data?” → **in scope** (soft AppSec)  
- “Write me a poem about cats” → **out of scope**  

A fixed topic list will both **false-refuse** soft security and **false-allow** clever chit-chat.

### What we implemented

File: `app/rag/scope.py`  
Config: `USE_LLM_SCOPE_GATE` (default **true**)

```text
decide_scope(question, route, llm, endpoints):
  if structural scan slots → related=true   # no LLM
  if obvious off-topic regex → related=false # no LLM
  if use_llm → Gemma JSON related yes/no
  else → keyword fallback
  on LLM error → related=true (fail-open)
```

### What “related” means

**In scope:** list/filter/explain/remediate/compare/existence about **this scan’s findings**, soft AppSec about the scan, endpoints/parameters/CWEs.

**Out of scope:** weather, jokes, pure world knowledge, pure chit-chat, compliance essays with no scan link.

### What the user sees when refused

Fixed product-boundary text: only answer **ingested scan findings**; will not invent answers. Empty store → prompt to **ingest** first.

### Justification line for reviewers

> Scope uses **cheap rules for obvious cases** and **Gemma for semantic relatedness** so we are not limited to keyword topics. The store still decides which findings exist after scope allows the question through.

---

# 9. Module-by-module justification

## 9.1 API — `app/api/`

| File | Role |
|------|------|
| `schemas.py` | Ingest/query contracts; reject bad JSON early |
| `routes.py` | Thin HTTP layer |

Endpoints: `/ingest`, `/query`, `/health`, `/scans/{id}/findings`.

## 9.2 Config & clients

| Piece | Why |
|-------|-----|
| Env settings | Keys out of git; portable providers |
| OpenAI-compatible LLM | Cerebras Gemma 4 / swap base URL |
| Separate embeddings client | Different vendor/model from chat |
| `LLM_REASONING_EFFORT=none` | Avoid thinking-token waste |

## 9.3 DB — SQLite + SQLAlchemy

Zero-ops system of record; exact filters; multi-scan via `scan_id`.

## 9.4 Ingestion — `app/ingestion/`

`pipeline.py`: replace scan → embed findings → rebuild BM25 → upsert knowledge.  
**N findings**, not hardcoded 15.

## 9.5 Retrieval — `app/retrieval/`

| Module | Role |
|--------|------|
| `findings_store.py` | Truth + search + `distinct_endpoints` |
| `filter_engine.py` | Set algebra (count/list/topics/path_param) |
| `taxonomy.py` | AppSec topics → keywords/CWEs (domain knowledge) |
| `synonyms.py` | Phrase expansion / concept bridges |
| `endpoint_utils.py` | Soft NL → **catalog** paths |
| `hybrid.py` | BM25 ∪ dense → RRF → CE |
| `bm25_index.py`, `cross_encoder.py`, `vector_store.py` | IR stack |

## 9.6 RAG — `app/rag/`

| Module | Role |
|--------|------|
| **`scope.py`** | **Product boundary: rules + Gemma relatedness** |
| `router.py` | `rule_based_route` operators + intent (not answer packs) |
| `planner.py` / `plan_schema.py` | Optional LLM FilterSpec |
| `generator.py` | Structured / LLM / row-bound fallbacks |
| `citations.py` | Gate IDs |
| `prompts.py` | Grounding policy (bind endpoint+param from rows) |
| `tools.py` / `tool_agent.py` | Optional multi-round tools (off by default) |
| `context.py` | Format blocks for LLM |

## 9.7 Services — `query_service.py`

Orchestrates stages 0–F. Still a thick module (honest maintainability limitation).

## 9.8 Tests & scripts

| Asset | Role |
|-------|------|
| `tests/*` (~100+) | FakeLLM/FakeEmbeddings; includes `test_scope_refusal.py` |
| `scripts/live_validate.py` | Live golden vs real Gemma |
| Demo shell scripts | Manual demos |

Golden tests use **sample IDs** — **test coupling**, not runtime answer packs.

---

# 10. Key functions & design contracts

| Function | Contract |
|----------|----------|
| `FindingsStore.replace_scan` | Authoritative replace; any N |
| `apply_filters` / `route_to_filter_spec` | Deterministic inventory algebra |
| `rule_based_route` | Extract operators; no FINDING answer packs |
| `resolve_soft_endpoints` | Catalog-only soft path mapping |
| `decide_scope` / `classify_scope_with_llm` | Product boundary; Gemma when soft |
| `SemanticPlanner.plan` | Soft plan JSON; low conf discarded |
| `HybridRetriever.retrieve` | Soft candidates + knowledge |
| `AnswerGenerator.generate` | Structured vs LLM vs row template |
| `gate_citations` | IDs ⊆ retrieved set |
| `IngestionPipeline.ingest` | Store + vectors + BM25 + knowledge |

### Anti-hallucination layers

1. Empty store / out-of-scope refuse  
2. Store-first inventory  
3. Empty existence → abstain  
4. Prompt rules  
5. Citation ID validation  

---

# 11. Models, providers, config

| Concern | Default choice | Why |
|---------|----------------|-----|
| Embeddings | Qwen3-Embedding-8B (ModelScope) | Soft paraphrase |
| Chat / plan / scope / answer | Cerebras `gemma-4-31b` | Latency + quality |
| Cross-encoder | MiniLM optional | Rerank precision |
| Tools agent | Off | Latency |

### Important env knobs

```text
USE_LLM_SCOPE_GATE=true      # Gemma relatedness for soft questions
USE_SEMANTIC_PLANNER=true    # LLM FilterSpec when rules soft
USE_DYNAMIC_SYNTHESIS=true   # LLM explain/remediate
USE_TOOL_AGENT=false         # multi-round tools off
LLM_BASE_URL / LLM_MODEL / LLM_API_KEY
RERANK_MODE=auto|light|cross_encoder
```

---

# 12. What is still “hardcoded” (honest inventory)

### A. Legitimate domain knowledge (defend)

- Severity vocabulary & order  
- Intent cue phrases (count, top-N, “is there”)  
- AppSec class words in taxonomy (`ssrf`, `idor`, `jwt`, …)  
- Synonym bridges (ATO ↔ auth cues)  
- Pattern playbooks  
- Prompt safety rules  
- Obvious off-topic short list (weather/joke) for **latency only** — soft AppSec uses Gemma  

### B. Schema (assignment)

- Finding JSON field names  

### C. Demo / tests (admit)

- Sample content is fintech-shaped  
- Goldens expect sample finding IDs  
- Some validation questions tuned on the sample  

### D. Not hardcoded (push this)

- Finding count (not fixed at 15)  
- Endpoint paths (from catalog)  
- Question → FINDING-00X answer dictionary  
- SSRF always `source_url` / fixed import path  
- Auth-triad / SSRF special answer templates (removed)  
- Scope for soft NL = **Gemma**, not only topics  

---

# 13. Tradeoffs matrix

| Decision | Benefit | Cost |
|----------|---------|------|
| SQLite truth | Exact inventory | Not multi-writer scale |
| FilterEngine first | No count hallucinations | Soft NL needs IR/LLM |
| Hybrid IR | Lexical + semantic | Complexity |
| **Gemma scope gate** | Soft relatedness | +0–1 small LLM call |
| Structural skip for scope | 0 cost on hard Qs | — |
| Fail-open on scope LLM error | Don’t false-refuse scan | Rare off-topic may slip if LLM down |
| Citation gate | Hard anti-hallucination | May strip over-eager refs |
| Row-bound templates offline | Works without answer LLM | Less fluent |
| Tools off | Latency | Fewer multi-hop tool strategies |
| Catalog endpoint match | Safe on new apps | Needs token overlap with path |
| Pattern playbooks | Transfer across verticals | Finite coverage |
| Sample goldens | Measurable quality | Look overfit if misread |

---

# 14. “Did you game the take-home?” defense

### What gaming would look like (we do **not**)

```text
if "SSRF" in question: return canned FINDING-007 essay
```

### What we did (normal engineering)

1. Built dual-store hybrid for assignment failure modes (inventory, abstain, citations).  
2. Used the sample for demos/tests.  
3. Curated AppSec taxonomy + pattern playbooks.  
4. **Removed** demo-specific generator templates and instance-flavored playbook prose.  
5. Endpoint mapping via **ingested catalog**.  
6. Scope via **rules + Gemma**, not a fixed “only these 15 answers” map.  
7. Live validation suite on the sample for quality measurement.

### 60-second generality demo

1. Edit a finding endpoint/title; re-ingest.  
2. Ask about that endpoint / severity → tracks **store**.  
3. Ask for absent class (RCE) → abstain.  
4. Ask weather → scope refuse.  
5. Soft “other users’ data” → Gemma related + hybrid path.

### One-liner

> Goldens are sample-coupled. Runtime is **store-coupled** and **schema-general**. Those are different.

---

# 15. What we are still missing

### Product / ML
- Not full open-domain NLU  
- Finite taxonomy + playbooks  
- Soft endpoint needs some path-token overlap  
- Large-scan embed cost/latency  
- No multi-scan comparison product UI  
- No live MITRE/OWASP sync  

### Engineering
- Thick `QueryService`  
- No multi-tenant auth/audit  
- Schema-only ingest (other scanner formats need adapters)  
- Limited production observability  

### Evaluation
- Live suite primarily on sample  
- LLM variance on prose  
- Scope gate quality depends on Gemma (usually strong; not formally red-teamed)  

### Explicitly out of scope for take-home
- Full GRC chatbot  
- “Any security question about the company forever”  

---

# 16. Healthcare / logistics / non-fintech

| Layer | Fintech demo | Other verticals |
|-------|--------------|-----------------|
| Engine | Same | Same |
| Ingest schema | Same shape | Same shape |
| Paths/titles | WealthPilot sample | Whatever is in **their** JSON |
| Playbooks | Pattern AppSec | Still useful |
| Industry law (HIPAA, etc.) | Not built-in | Need finding text +/or extra docs |

**Phrase:** demo target is fintech; **system is scan-grounded AppSec**, not a bank-only bot.

---

# 17. How to demo & what to say live

### 10-minute script

1. `/health` — counts, model, stack  
2. CRITICAL list — **0 LLM**, exact  
3. RCE existence — abstain  
4. Weather — **scope refuse**  
5. Soft access-control phrasing — Gemma scope + hybrid/answer  
6. Explain/fix SQLi or IDOR — row-bound endpoint/param  
7. Optional: re-ingest modified JSON  

### Claims to avoid

- “Answers any natural language question.”  
- “Zero hardcoding of any kind.”  
- “Works on any scanner export without schema mapping.”  

### Strong claims

- Store-first inventory  
- Citation-gated IDs  
- Scope boundary (rules + Gemma)  
- Catalog endpoints + pattern knowledge  
- Honest limits  

---

# 18. Likely reviewer questions (Q&A)

### Q: Why regex in the router?
**A:** Operators (count, severity, CWE, path-param). Soft language uses taxonomy, catalog, hybrid, planner, and Gemma scope—not an answer key.

### Q: Why not embeddings for everything?
**A:** Inventory completeness and exact severity/CWE algebra fail under top‑k vectors alone.

### Q: How do you know a question is off-topic?
**A:** Structural rules and obvious junk short-circuit; otherwise **Gemma returns `related` JSON**. Not keyword-only for soft AppSec.

### Q: How many LLM calls per query?
**A:** Hard inventory **0**. Soft explain typically **2–3** (scope ± plan + answer). Tools off by default. Max ~4 with repair.

### Q: Did you hardcode FINDING-007 for SSRF?
**A:** No. Retrieval + row fields + pattern playbook. No fixed ID pack.

### Q: What if Gemma is down for scope?
**A:** Fail-open to related=true for non-obvious cases; still citation-gated after retrieval. Empty store / obvious junk still refuse without LLM.

### Q: Is this only for the 15 sample findings?
**A:** Sample is the demo fixture. Ingest accepts any N of the same schema; catalog and filters are dynamic.

### Q: Production ready?
**A:** Strong take-home / prototype. Missing multi-tenant auth, scale eval, formal multi-scan goldens.

### Q: Why so much code vs one LangChain chain?
**A:** Assignment fails on inventory, abstain, and citations—not on chatbot demos. Complexity sits where correctness matters.

---

# 19. File map (study checklist)

| Priority | Path | Know |
|----------|------|------|
| P0 | `app/services/query_service.py` | Full orchestration |
| P0 | `app/rag/scope.py` | **Scope gate + Gemma relatedness** |
| P0 | `app/retrieval/filter_engine.py` | Precision path |
| P0 | `app/rag/router.py` | Rules / operators |
| P0 | `app/rag/generator.py` | Answer paths + row fallbacks |
| P0 | `app/rag/citations.py` | Gate |
| P1 | `app/retrieval/hybrid.py` | Soft IR |
| P1 | `app/retrieval/taxonomy.py` | Topics |
| P1 | `app/retrieval/endpoint_utils.py` | Catalog mapping |
| P1 | `app/ingestion/pipeline.py` | Ingest |
| P1 | `app/rag/planner.py` | Semantic plan |
| P1 | `app/rag/prompts.py` | Grounding |
| P1 | `app/config.py` | Knobs including `USE_LLM_SCOPE_GATE` |
| P2 | `app/clients/llm.py` | Provider + FakeLLM scope behavior |
| P2 | `tests/test_scope_refusal.py` | Scope unit coverage |
| P2 | `scripts/live_validate.py` | Live quality bar |
| P2 | `README.md` | External story |
| P2 | `data/knowledge/appsec_guides/*` | Pattern playbooks |

---

# 20. Glossary

| Term | Meaning here |
|------|----------------|
| **System of record** | SQLite findings |
| **FilterSpec / FilterEngine** | Deterministic set algebra on full inventory |
| **Precision path** | Inventory without free-form LLM counts |
| **Soft path** | Hybrid IR + LLM narration |
| **Scope gate** | Is this question about the scan? (rules + Gemma) |
| **Relatedness** | LLM JSON `related: true\|false` for soft questions |
| **Fail-open (scope)** | On LLM error, allow through rather than false refuse |
| **Abstain** | Refuse to invent when scan doesn’t support claim |
| **Citation gate** | Server validation of finding IDs |
| **Catalog** | Distinct endpoints from current scan |
| **Taxonomy** | AppSec topic → keywords/CWEs |
| **RRF** | Reciprocal Rank Fusion |
| **Dynamic synthesis** | LLM explain/remediate from retrieved rows |
| **Semantic planner** | LLM → structured query plan |
| **Row-bound template** | Offline answer built only from store fields |

---

# Closing: 30-second pitch

> AppSecure is a **store-first hybrid RAG** for application security findings. Inventory and existence are exact (SQLite). Soft questions use hybrid retrieval and Gemma for **scope**, optional **planning**, and **narration**, always bound to retrieved rows with a **citation gate**. Knowledge is pattern-level AppSec. The demo target is a fintech mock scan; ingest and query are **schema-general**. Hard questions cost **zero** chat LLM calls; soft explain is usually **two to three**. We optimized for **anti-hallucination and assignment failure modes**, not open-domain chat. Limits are soft NL coverage, evaluation breadth, and production multi-tenancy—not a secret answer key over 15 findings.

---

*Document version: updated for LLM scope gate (`USE_LLM_SCOPE_GATE`), call-budget section, generalization (catalog endpoints, pattern playbooks, row-bound templates), and off-topic refusal behavior.*
