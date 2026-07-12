# AppSecure Vulnerability Explainer RAG  
## Study Guide, Architecture Justification & Honest Defense Notes

**Purpose of this document**  
Use this before a review / viva / submission write-up. It explains **what we built**, **why we built it that way**, **what is still hardcoded**, **tradeoffs**, **what we are missing**, and **how to answer “did you game the sample?”**

**Audience**  
You (author) + a technical reviewer who may be skeptical of regex, templates, and sample-tuned tests.

**Product one-liner**  
A FastAPI service that answers natural-language questions **over ingested application-security scan findings**, with **citations**, **hybrid retrieval**, and **hard anti-hallucination controls**. Demo dataset is a fictional fintech API; the **engine is scan-schema-general**, not fintech-product-locked.

---

# Table of contents

1. [Elevator pitch & problem](#1-elevator-pitch--problem)  
2. [What success looks like for this assignment](#2-what-success-looks-like-for-this-assignment)  
3. [End-to-end architecture](#3-end-to-end-architecture)  
4. [Why not pure RAG / pure agent / pure SQL](#4-why-not-pure-rag--pure-agent--pure-sql)  
5. [Data model & dual store](#5-data-model--dual-store)  
6. [Request lifecycle (query path)](#6-request-lifecycle-query-path)  
7. [Module-by-module justification](#7-module-by-module-justification)  
8. [Key functions & design contracts](#8-key-functions--design-contracts)  
9. [Models, providers, config](#9-models-providers-config)  
10. [What is still “hardcoded” (honest inventory)](#10-what-is-still-hardcoded-honest-inventory)  
11. [Tradeoffs matrix](#11-tradeoffs-matrix)  
12. [“Did you game the take-home?” defense](#12-did-you-game-the-take-home-defense)  
13. [What we are still missing](#13-what-we-are-still-missing)  
14. [Healthcare / logistics / non-fintech](#14-healthcare--logistics--non-fintech)  
15. [How to demo & what to say live](#15-how-to-demo--what-to-say-live)  
16. [Likely reviewer questions (Q&A)](#16-likely-reviewer-questions-qa)  
17. [File map (study checklist)](#17-file-map-study-checklist)  
18. [Glossary](#18-glossary)

---

# 1. Elevator pitch & problem

### Problem
PTaaS / AppSec platforms produce **structured scanner findings** (severity, CWE, endpoint, evidence, remediation). Users want to ask:

- “What are all CRITICAL findings?”  
- “Explain the IDOR on accounts.”  
- “How do I fix the SQLi?”  
- “Is there RCE?”  
- “Compare the two IDORs.”

### Naive approaches fail

| Approach | Typical failure |
|----------|-----------------|
| Stuff JSON into a prompt | Misses full inventory; invents IDs; unstable |
| Embed findings + chat only | Soft match; wrong top‑k; incomplete lists |
| Free-form LLM “count CRITICAL” | Hallucinates counts (“15 CRITICAL” when there are 2) |
| SQL only | Weak on soft phrasing (“other users’ profiles”) |
| Agent with tools only | Latency; tool loops; still invents if not gated |

### Our approach (one sentence)

**Store decides which findings exist; hybrid IR retrieves soft matches; LLM plans soft filters and narrates answers; server-side citation gate enforces that every `FINDING-*` ID was actually retrieved.**

---

# 2. What success looks like for this assignment

The assignment asks for a **Vulnerability Explainer RAG Agent** with roughly:

| Requirement | How we address it |
|-------------|-------------------|
| Ingest scan + knowledge | `POST /ingest` → SQLite + Chroma + BM25 |
| Natural language Q&A | `POST /query` |
| Citations | Findings + knowledge refs; IDs validated |
| Anti-hallucination | Empty existence → abstain; citation gate |
| Sample questions | Covered by demos + `scripts/live_validate.py` |
| Extensible knowledge | Bundled OWASP/CWE/playbooks + optional `reference_documents` |

**Submission-ready means:** design is coherent, demo works, tests pass, limitations are honest—not “production multi-tenant GRC platform.”

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
     HybridRetriever + FilterEngine
              │
     Router / SemanticPlanner
              │
     AnswerGenerator + Citation gate
              │
              ▼
         QueryResponse
```

### Design principle (memorize this)

> **LLM proposes; store disposes.**  
> The model may suggest filters and write prose. It may **not** invent finding IDs, severities, or endpoints that are not in retrieved context.

---

# 4. Why not pure RAG / pure agent / pure SQL

### Why dual store instead of “vectors only”

Findings are **structured records** (severity enum, CWE, endpoint). Inventory questions are **set algebra**, not nearest-neighbor search.

- “All CRITICAL” must return **complete set**, not top‑5 similar chunks.  
- “Is there RCE?” must be able to return **empty + abstain**.  
- Citations must be **stable IDs**, not approximate text snippets alone.

**SQLite = system of record.**  
**Chroma = soft retrieval + knowledge.**  
**BM25 = lexical exactness** (CWE-89, path tokens, titles).

### Why hybrid BM25 + dense + RRF + cross-encoder

| Signal | Catches |
|--------|---------|
| BM25 | Exact tokens: `CWE-918`, `JWT`, path fragments |
| Dense embeddings | Paraphrase: “other users’ accounts” ≈ IDOR |
| RRF | Merge ranked lists without score calibration hell |
| Cross-encoder (optional) | Re-rank top candidates for precision |

### Why citation gate

Prompts alone do not stop models from inventing `FINDING-999`.  
Server code **intersects** claimed IDs with retrieved IDs (and can strip unknown IDs from answer text).

### Why tools agent is off by default

Multi-round tool calling improves hard multi-hop cases but costs latency and can still invent if not gated. Default path: **filter-first hybrid + optional planner**. Tool agent remains optional (`USE_TOOL_AGENT`).

---

# 5. Data model & dual store

### Scan schema (ingest contract)

Matches assignment-style JSON:

```text
scan_id, target, scan_timestamp
findings[]:
  id, title, severity, cwe_id, owasp_category,
  endpoint, method, parameter, description,
  evidence, remediation_hint
```

**Important:** Ingest is **N-agnostic**. 15 sample findings is the demo file size, not a code limit. A reviewer can ingest 40 findings of the same shape.

### SQLite (`FindingsStore`)

- `replace_scan(scan_id, findings)` — authoritative rows for that scan  
- Filters: severity, CWE, endpoint substring, keywords  
- `distinct_endpoints(scan_id)` — **live catalog** for soft endpoint mapping  

### Chroma (`VectorStore`)

- Finding narratives (for soft retrieval)  
- Knowledge chunks (OWASP, CWE, playbooks)  
- Metadata: doc_type, cwe_id, owasp, topics  

### BM25 (`FindingsBM25Index`)

- Rebuilt on ingest over all store findings  
- Complements dense search when embeddings under-match exact tokens  

### Knowledge layers

| Layer | Role |
|-------|------|
| `data/sample_findings.json` | Demo truth (fintech-shaped **content**) |
| `data/knowledge/owasp_top10_2021/` | Standard categories |
| `data/knowledge/cwe/` | CWE definitions used by sample + general |
| `data/knowledge/appsec_guides/` | **Pattern** playbooks (SSRF classes, JWT none, BOLA, SQLi, auth) |

Playbooks were rewritten to be **pattern-first**, not “FINDING-007 answer packs.” Instance fields (endpoint/parameter) should come from the **finding row** at answer time.

---

# 6. Request lifecycle (query path)

Primary orchestrator: `app/services/query_service.py` → `QueryService.query()`.

### Stage A — Route / plan

1. `rule_based_route(question)` — extract operators (severity, CWE, count, top_n, topics, path-param shape, soft endpoint tokens).  
2. Resolve soft endpoints against **catalog**: `resolve_soft_endpoints(question, distinct_endpoints)`.  
3. If rules are not “confident,” optional **SemanticPlanner** (LLM → JSON FilterSpec-like plan), merged with rules.  
4. High-confidence rule ops **skip** planner (latency + stability).

### Stage B — Precision path (FilterEngine)

When the question is inventory-like:

- count / top_n  
- severity lists  
- include/exclude topics or phrases  
- path_param_only  
- strict endpoint filters  

→ `apply_filters(all_findings, FilterSpec)` on **full inventory** (no top‑k loss).

Empty set on existence → **abstain**.

### Stage C — Soft path (HybridRetriever)

For explain / soft list / free text:

- BM25 ∪ dense → RRF → optional cross-encoder  
- Knowledge vectors retrieved for playbooks / CWE / OWASP  
- Class constraints (topic keywords) may narrow candidates  

### Stage D — Generate

| Intent family | Answer path |
|---------------|-------------|
| list / summary / count / existence (yes set) | Structured templates from store |
| explain / remediation / compare | LLM JSON (dynamic synthesis) if enabled |
| LLM down / fail | Row-bound template fallback (`_template_explain`, `_template_compare`) |

### Stage E — Citation gate

`gate_citations` / `validate_finding_ids`:

- `findings_referenced ⊆ allowed retrieved IDs`  
- strip hallucinated IDs from answer when possible  

### Response fields (explainability)

`answer`, `citations`, `findings_referenced`, `query_intent`, `abstained`, `latency_ms`, `answer_source` (`structured` \| `llm` \| `template` \| `abstain`), `model_used`.

---

# 7. Module-by-module justification

## 7.1 API — `app/api/`

| File | Role | Why |
|------|------|-----|
| `schemas.py` | Pydantic contracts | Reject malformed ingest early; stable OpenAPI |
| `routes.py` | HTTP wiring | Thin layer; business logic in services |

**Endpoints**

- `POST /ingest` — replace scan findings + reindex  
- `POST /query` — Q&A  
- `GET /health` — counts, model, retrieval stack  
- `GET /scans/{scan_id}/findings` — debug / explainability  

**Why FastAPI:** assignment-friendly OpenAPI, validation, async-ready, standard for Python services.

---

## 7.2 Config & clients — `app/config.py`, `app/clients/`

| Piece | Justification |
|-------|----------------|
| Env-based settings | Keys never committed; portable across providers |
| OpenAI-compatible LLM client | Swap Cerebras / ModelScope / others via base URL + model |
| Separate embeddings client | Embeddings and chat often different vendors |
| `LLM_REASONING_EFFORT=none` | Avoid “thinking” models burning tokens / latency |

**Default stack (as documented):** Qwen3 embeddings (ModelScope) + Cerebras `gemma-4-31b` for chat/planner.

---

## 7.3 DB — `app/db/`

SQLAlchemy models + SQLite session.

**Why SQLite for a take-home**

- Zero infra  
- Exact filters and re-ingest  
- Easy to inspect  
- Multi-scan ready via `scan_id`  

**Tradeoff:** not multi-writer production scale; fine for demo.

---

## 7.4 Ingestion — `app/ingestion/`

| File | Role |
|------|------|
| `pipeline.py` | Orchestrate store replace, vector upsert, BM25 rebuild, knowledge load |
| `finding_documents.py` | Turn rows into embeddable text + metadata |
| `knowledge_loader.py` | Load OWASP/CWE/playbooks from disk |

**Why re-embed on every ingest:** simplicity and correctness for demo.  
**Tradeoff:** large scans cost more embedding calls.

**Why knowledge re-upserted:** keep guides available even after fresh chroma; cheap for small corpus.

---

## 7.5 Retrieval — `app/retrieval/`

### `findings_store.py`
System of record. Search/filter APIs used by FilterEngine and hybrid.

### `filter_engine.py`
**Set algebra** on full inventory:

- include/exclude severity  
- CWE, OWASP, endpoint  
- include/exclude phrases (expanded via synonyms)  
- include/exclude topics (taxonomy → keywords/CWEs; phrase **OR** CWE)  
- `path_param_only` (`{` in endpoint/parameter)  
- top_n after severity sort  

**Why:** inventory questions must not depend on vector top‑k.

### `taxonomy.py`
Curated AppSec topics (injection, authn, authz, ssrf, secrets, mass_assignment, …).

**Why:** maps soft language to structured filters without finding-ID packs.  
**Not** industry-specific (not “payments company only”).

### `synonyms.py`
Phrase extraction + expansion + light concept bridges (e.g. account takeover ↔ auth bypass / JWT cues).

**Why:** improve recall without hardcoding sample finding IDs.

### `endpoint_utils.py`
- Extract explicit API paths from questions  
- Soft tokens (“payments endpoint”, “login page”)  
- Match against **live catalog** (substring / last segment)  
- Detect unknown explicit paths → abstain inventing vulns on them  

**Why not Levenshtein-first:** edit distance on full paths mis-maps; catalog segment match is safer.

### `hybrid.py`
Main soft retriever: BM25 ∪ dense → RRF → CE; special cases for summary/path-param/existence precision.

### `bm25_index.py`, `cross_encoder.py`, `rerank.py`, `vector_store.py`
Implementation details of hybrid IR.

---

## 7.6 RAG — `app/rag/`

### `router.py` — `rule_based_route`
Extracts:

- finding IDs typed by user  
- severities / exclude severities  
- CWE / OWASP  
- endpoint path regex + soft “X endpoint”  
- path_param_only  
- topics via taxonomy  
- intent cues (list, explain, remediation, existence, compare, cluster, …)  
- operators (count, top_n, classify buckets, data_impact)  

**Why regex/rules exist:** deterministic precision for operators.  
**What they are NOT:** a map from question → fixed FINDING-00X answer pack.

**Why this is not “Fintech endpoint hardcoding”:**  
Product paths are not the allowlist. Soft tokens resolve against **whatever endpoints were ingested**. Explicit `/api/v2/transfer` is extracted generically.

### `planner.py` + `plan_schema.py`
LLM emits structured plan JSON; merge with rules; resolve endpoints against catalog.

**Why optional:** soft NL when rules under-specify.  
**Why not always on:** latency; rules already handle many hard questions.

### `generator.py`
- Structured answers for inventory  
- LLM JSON for synthesis when enabled  
- **Row-bound** fallbacks if LLM unavailable (`_template_explain`, `_template_compare`)  
- Priority “why” built from store fields (severity, CWE, endpoint, param, title, hint)  

**Removed earlier:** SSRF/auth-triad special templates that assumed sample params/paths.

### `citations.py`
Build citations; gate IDs; optional answer scrubbing.

### `prompts.py`
System/user prompts for planner and answerer. Emphasize: never invent findings; bind endpoint/parameter from rows.

### `tools.py` + `tool_agent.py`
Optional multi-step tool agent over findings store. Off by default for latency.

### `context.py`
Format finding/knowledge blocks for LLM context.

---

## 7.7 Services — `query_service.py`

Thick orchestrator (honest limitation: still a “god service”).

Responsibilities:

- rule confidence & planner skip logic  
- FilterEngine precision branch  
- hybrid branch  
- optional tool agent  
- generation + gate  
- latency measurement  

**Why one service for take-home:** clear single path to read.  
**Future:** split plan → filter → retrieve → generate → gate modules.

---

## 7.8 Tests & scripts

| Asset | Role |
|-------|------|
| `tests/*` | ~95 unit tests with FakeLLM / FakeEmbeddings (no network) |
| `scripts/live_validate.py` | Live golden suite against running server + real keys |
| `scripts/demo_queries.sh`, `hard_queries.sh` | Manual demos |

**Golden tests use sample IDs.** That is **test coupling**, not runtime answer packs. Be ready to say that out loud.

---

# 8. Key functions & design contracts

Study these as “contracts.”

| Function | Contract |
|----------|----------|
| `FindingsStore.replace_scan` | Authoritative replace for `scan_id`; N findings |
| `FindingsStore.list_all` / `search` | Truth for filters |
| `route_to_filter_spec` / `apply_filters` | Deterministic set algebra; no LLM counts |
| `rule_based_route` | Extract operators + intent; no answer packs |
| `resolve_soft_endpoints` | NL resource cue → catalog paths only |
| `SemanticPlanner.plan` | Soft FilterSpec proposal; low confidence discarded |
| `merge_plan_into_route` | Rules win on hard slots when already set |
| `HybridRetriever.retrieve` | Soft candidates + knowledge |
| `AnswerGenerator.generate` | Structured vs LLM vs template fallback |
| `gate_citations` | IDs must be subset of retrieved set |
| `IngestionPipeline.ingest` | Store + vectors + BM25 + knowledge |

### Anti-hallucination layers (defense-in-depth)

1. Store-first inventory  
2. Empty existence → abstain  
3. Prompt rules  
4. Citation ID validation  
5. Optional unknown-path abstain  

---

# 9. Models, providers, config

| Concern | Choice | Why |
|---------|--------|-----|
| Embeddings | Strong general embedder via OpenAI-compatible API | Soft paraphrase retrieval |
| Chat / planner | Fast OpenAI-compatible model (e.g. Cerebras Gemma) | Latency budget for plan+answer |
| Cross-encoder | MiniLM (optional auto/light) | Rerank precision; download cost in CI |
| Temperature | Low for structured JSON | Stability |

**Config knobs (conceptual):**

- `USE_SEMANTIC_PLANNER`  
- `USE_DYNAMIC_SYNTHESIS`  
- `USE_TOOL_AGENT` (default false)  
- `RERANK_MODE` (`auto` / `cross_encoder` / `light`)  
- `LLM_BASE_URL`, `LLM_MODEL`, keys  

---

# 10. What is still “hardcoded” (honest inventory)

### A. Legitimate domain hardcoding (defend as product knowledge)

- Severity vocabulary & order  
- Intent cue phrases  
- AppSec class abbreviations (`ssrf`, `idor`, `jwt`, …)  
- Taxonomy topics → CWE/keywords  
- Synonym bridges for common AppSec concepts  
- Playbook **patterns** (not finding IDs)  
- Prompt safety rules  

This is analogous to a security product understanding “SQLi” and “IDOR”—not hardcoding one customer’s URL map.

### B. Schema hardcoding (assignment contract)

- Finding JSON field names  
- Severity labels expected by filters  

### C. Demo / test hardcoding (admit this)

- Sample dataset is fintech-shaped **content**  
- Unit/live goldens expect sample finding IDs  
- Some router cues tuned on hard questions we saw in validation  

### D. What is **not** hardcoded (push this)

- Number of findings (not fixed at 15)  
- Endpoint paths (catalog from SQLite)  
- Answer packs FINDING-00X  
- SSRF parameter always `source_url`  
- Auth triad special generator templates (removed)  

---

# 11. Tradeoffs matrix

| Decision | Benefit | Cost |
|----------|---------|------|
| SQLite truth | Exact inventory; simple | Not distributed scale |
| Chroma | Zero-ops vectors | Local persistence; not cloud vector DB |
| Rules + FilterEngine | No count hallucinations; ms latency | Soft NL incomplete |
| Optional LLM planner | Better soft filters | Latency; provider variance |
| Hybrid IR | Lexical + semantic | Complexity; CE download |
| Citation gate | Hard anti-hallucination | May strip useful but uncited IDs if LLM forgets |
| Templates offline | Works without LLM | Less fluent prose |
| Tool agent off | Latency | Fewer multi-hop tool strategies |
| Taxonomy | Interpretable class filters | Finite coverage |
| Catalog endpoint match | Safe on new apps | Needs token overlap with path |
| Golden suite on sample | Measurable quality | Looks overfit if misinterpreted |

---

# 12. “Did you game the take-home?” defense

### What “gaming” would look like (we did **not** do this)

```text
if "SSRF" in question:
    return FINDING-007 canned answer
```

Runtime has **no** question → fixed finding-ID answer dictionary.

### What we *did* do (normal engineering)

1. **Built against the assignment sample** for demos and tests (everyone does).  
2. **Curated AppSec taxonomy and playbooks** so soft questions work.  
3. **Added precision operators** after seeing pure vector RAG fail inventory.  
4. **Generalized** away sample-specific generator templates and instance-flavored playbooks.  
5. **Live validation** against the sample to measure quality.

### How to prove generality in 60 seconds

1. Change a finding title/endpoint in a copy of the JSON; re-ingest.  
2. Ask for that endpoint / severity — answer tracks the **store**, not old memory.  
3. Ask for a vuln class **not** in the scan → abstain.  
4. Show `distinct_endpoints` drives soft endpoint mapping.

### How to admit limitations without collapsing

> Goldens are sample-coupled. Architecture is store-coupled. Those are different things.

---

# 13. What we are still missing

Be honest in the interview. Missing ≠ automatic fail for a take-home.

### Product / ML

| Gap | Impact |
|-----|--------|
| Not full open-domain NLU | Weird paraphrases can mis-route |
| Finite taxonomy | Novel slang needs hybrid/LLM |
| No multi-scan comparison UI | Single-scan demo focus |
| No live MITRE/OWASP sync | Offline curated knowledge |
| Playbook chunking coarse | Section-level retrieval could be better |
| Soft endpoint needs token overlap | “funds transfer screen” may miss `/transfer` if no shared token |
| Large scan embed cost | Rate limits / latency |
| Tool agent underused | Latency choice |

### Engineering

| Gap | Impact |
|-----|--------|
| Thick `QueryService` | Harder to maintain |
| Limited multi-tenant auth / audit | Out of scope |
| No production observability stack | Only latency_ms + logs |
| Schema-only ingest | Arbitrary scanner exports need adapters |
| First CE download | CI friction (use `RERANK_MODE=light`) |

### Evaluation

| Gap | Impact |
|-----|--------|
| Live suite on sample only | Doesn’t certify every vertical |
| No dual-scan golden | Multi-tenant confidence limited |
| LLM variance | Same question may differ slightly in prose |

### Nice-to-haves (not required to claim success)

- Graph-based finding relationships  
- Automatic retest after fix  
- RBAC on API  
- Streaming SSE answers  
- UI dashboard  

---

# 14. Healthcare / logistics / non-fintech

### Claim

**The engine is vertical-agnostic for AppSecure-shaped findings.**  
The **demo content** is fintech.

### What transfers automatically

- Any endpoints in the new scan → catalog + filters  
- Any severities/CWEs → structured ops  
- IDOR/SQLi/SSRF/JWT patterns → taxonomy + playbooks  
- Answers cite **that scan’s** rows  

### What does **not** transfer automatically

- HIPAA-specific legal guidance  
- Logistics business process advice  
- Completely different export formats  

**Those need:** finding text quality + optional `reference_documents` +/or new playbooks—not a code fork.

### Phrasing for review

> We didn’t build a fintech bot. We built a scan-grounded AppSec explainer. The sample happens to be a wealth API.

---

# 15. How to demo & what to say live

### Demo script (10 minutes)

1. **Health** — show findings_count, models, retrieval stack.  
2. **Hard inventory** — “How many CRITICAL?” → structured, fast, exact.  
3. **List** — “All critical findings” → full set with IDs.  
4. **Abstain** — “Is there RCE?” → no invent.  
5. **Explain** — IDOR or SQLi → endpoint/param from row + remediation.  
6. **Soft** — “other users’ accounts” / payments endpoint → hybrid + catalog.  
7. **Compare** — two IDORs or auth issues.  
8. *(Optional)* Re-ingest a modified JSON to show generality.

### What to say when latency spikes

> Soft paths may call planner and/or LLM; inventory stays local SQL. Provider load can push some soft queries higher; architecture still separates hard vs soft.

### What not to claim

- “Answers any natural language question about security.”  
- “Works on any scanner export without schema mapping.”  
- “Zero hardcoding of any kind.”  

---

# 16. Likely reviewer questions (Q&A)

### Q: Why regex in the router?

**A:** For **operators** (count, severity, CWE, path-param shape), regex/rules are precise and cheap. Soft language uses taxonomy, catalog endpoints, hybrid IR, and optional LLM planner. Regex is not an answer key for the sample.

### Q: Why not embeddings for everything?

**A:** Embeddings fail completeness on inventory and are weak for exact CWE/severity algebra. Dual store is intentional.

### Q: Why SQLite not Postgres?

**A:** Take-home zero-ops. Abstraction allows upgrade later.

### Q: Why Chroma not Pinecone?

**A:** Local demo, no cloud vector billing, persistent enough for assignment.

### Q: Did you hardcode FINDING-007 for SSRF?

**A:** No. SSRF questions retrieve via CWE/keywords/hybrid; answers bind **retrieved rows**. Playbooks describe SSRF patterns, not a fixed finding ID.

### Q: What if LLM is down?

**A:** Inventory still works. Explain falls back to row-bound templates (endpoint, parameter, description, remediation_hint from store).

### Q: How do you prevent hallucination?

**A:** Store-first filters, abstain on empty existence, prompt rules, citation gate on finding IDs.

### Q: Is this production ready?

**A:** Strong prototype for PTaaS-style Q&A. Missing multi-tenant auth, scale testing, formal eval on multi-scan corpora, ops hardening.

### Q: Why so much code vs a single LangChain chain?

**A:** Assignment failure modes are structural (inventory, abstain, citations). A thin chain demos well until it invents CRITICAL counts. Complexity is concentrated where correctness matters.

### Q: What did you deliberately remove while generalizing?

**A:** SSRF/auth-triad special templates; sample-instance playbook prose; priority text that mentioned fintech/financial records; soft endpoint mapping that depended on product path lists rather than catalog.

---

# 17. File map (study checklist)

Read in this order before viva:

| Priority | Path | Know |
|----------|------|------|
| P0 | `app/services/query_service.py` | Full orchestration |
| P0 | `app/retrieval/filter_engine.py` | Precision path |
| P0 | `app/rag/router.py` | Rules / operators |
| P0 | `app/rag/generator.py` | Answer paths |
| P0 | `app/rag/citations.py` | Gate |
| P1 | `app/retrieval/hybrid.py` | Soft IR |
| P1 | `app/retrieval/taxonomy.py` | Topics |
| P1 | `app/retrieval/endpoint_utils.py` | Catalog mapping |
| P1 | `app/ingestion/pipeline.py` | Ingest |
| P1 | `app/rag/planner.py` | Semantic plan |
| P1 | `app/rag/prompts.py` | Grounding policy |
| P2 | `app/clients/llm.py` | Provider quirks |
| P2 | `app/config.py` | Knobs |
| P2 | `scripts/live_validate.py` | Quality bar |
| P2 | `README.md` | External story |
| P2 | `data/knowledge/appsec_guides/*` | Pattern playbooks |

---

# 18. Glossary

| Term | Meaning here |
|------|----------------|
| **System of record** | SQLite findings; source of truth |
| **FilterSpec** | Structured filter applied to full inventory |
| **Precision path** | Deterministic filter/template without free-form LLM inventory |
| **Soft path** | Hybrid retrieval + LLM narration |
| **Abstain** | Refuse to invent when scan doesn’t support claim |
| **Citation gate** | Server validation of finding IDs |
| **Catalog** | Distinct endpoints from current scan |
| **Taxonomy** | AppSec topic → keywords/CWEs map |
| **RRF** | Reciprocal Rank Fusion of ranked lists |
| **Dynamic synthesis** | LLM explain/remediate from retrieved rows |
| **Semantic planner** | LLM → structured query plan JSON |

---

# Closing: how to frame the whole project in 30 seconds

> AppSecure is a **store-first hybrid RAG** for application security findings. Inventory and existence are exact because they come from SQLite set algebra. Soft questions use hybrid retrieval and an LLM that only narrates retrieved rows, with a citation gate. Knowledge is pattern-level AppSec (OWASP/CWE/playbooks). The demo target is a fintech mock scan, but ingest and query are schema-general for any vertical. We optimized for **anti-hallucination and assignment failure modes**, not for open-domain chat. Remaining limits are soft NL coverage, evaluation breadth, and production multi-tenancy—not a secret answer key over 15 findings.

---

*Document version: aligned with repo after generalization commits (`pattern playbooks`, catalog endpoints, row-bound templates). Re-read `generator.py` / `endpoint_utils.py` if you pull newer changes.*
