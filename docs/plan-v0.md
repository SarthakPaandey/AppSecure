# Plan v1 (Approved Direction): Essay-Aligned Surgical 9/10 Path

**Status:** Implemented (surgical path).  
**Source:** Essay thesis + prior plan-v0 + **user-approved adjustments** (below).  
**Strategy:** Surgical improvement, **not** a large rewrite.

**Thesis (keep):**

> Exact questions are answered from the complete structured scan; ambiguous questions get one constrained planner + hybrid retrieval; one grounded generator explains only verified findings with server-validated citations.

**Public docs:** Never claim “this is a 9/10.” Keep scores private. README focuses on design, tests, evidence, limitations.

---

## Approved adjustments (must follow)

| # | Adjustment |
|---|------------|
| 1 | **Vector filter fail-closed → Phase 1** (mandatory). No bare retry if `where` fails. |
| 2 | **Planner `in_scope` conservative:** high-conf out → refuse; malformed/low-conf/timeout → **fail open** to retrieval; empty support → abstain. |
| 3 | **Do not over-refactor** RouteResult / QueryPlan / FilterSpec. Add only `in_scope` + `execution` if needed; adapters only. |
| 4 | **Wording:** Planner = ambiguous only. Generator = narrative (explain/remediate/compare/risk), even when routing is exact. Inventory = 0 LLM. |
| 5 | **Catalog-aware finding IDs** after scan load; test `SHIP-AUTH-01`, `web:xss:44`, etc. |
| 6 | **No score claims** in README/repo. |
| 7 | **Phase order** reordered for safety (see below). |

---

## Target default path

```text
load scan + catalog
→ parse structural fields (universal syntax)
→ exact structured? → SQLite FilterEngine → template → citation gate
→ else optional semantic planner (≤1 LLM)
→ validate plan (rules win on explicit slots)
→ in_scope high-conf false? refuse
→ planner fail / low-conf out? fail open → retrieve
→ BM25 ∪ dense → RRF (CE off by default)
→ verify scan_id isolation
→ knowledge (doc_type filtered, fail-closed)
→ empty existence? abstain
→ inventory template OR grounded generator (≤1 + optional 1 repair)
→ citation gate
```

### LLM budget (defaults)

| Path | Calls |
|------|------:|
| Count / list CRITICAL / A01 / top-N | **0** |
| Explain/fix with clear rules | **1** (generator only) |
| Soft semantic | **2** (planner + generator) |
| Unsupported existence | **0–1** |
| Max normal | **≤3** (with one repair) |

**Default off / not in story:** dedicated scope LLM, tool agent, required CE.

---

## Abstraction policy (no risky rewrite)

```text
RouteResult  → explicit user syntax (rules)
QueryPlan    → optional semantic interpretation (+ in_scope, execution)
FilterSpec   → SQLite executor input (unchanged role)
```

Adapters only:

- `route_to_filter_spec`
- merge/validate plan into route
- plan concepts → existing phrases/topics

Do **not** rename every type or rewrite all tests for purity.

---

## Planner `in_scope` policy

| Situation | Behavior |
|-----------|----------|
| Rules: obvious junk (weather, recipe, joke) | Deterministic refuse |
| Planner `in_scope=false` **high** confidence | Refuse |
| Planner malformed JSON | Fail open → hybrid/safe path |
| Planner out of scope **low** confidence | Fail open → retrieve |
| Planner timeout / provider error | Fail open → retrieve; abstain if unsupported |
| Retrieval finds no support | Grounded abstention |

**Rule:** Planner failure ≠ automatic refusal. No verified support = abstention.

---

## Implementation phases (final order)

### Phase 1 — Correctness and defaults

1. **Confirm/fix** Chroma filtered query: fail closed (no unfiltered retry).  
   - File: `app/retrieval/vector_store.py`  
   - If already fail-closed, re-verify + keep isolation tests.  
2. Cross-scan isolation test (failed filtered query cannot leak other scan).  
3. Defaults:  
   - `USE_LLM_SCOPE_GATE=false`  
   - `USE_TOOL_AGENT=false`  
   - `RERANK_MODE=light`  
   - `CROSS_ENCODER_ENABLED=false`  
4. Default query path does **not** invoke scope LLM or tool agent.  
5. `.env.example` matches defaults.  
6. `pytest` green.

**Exit:** Safer + simpler even if work stops here.

---

### Phase 2 — Held-out scan proof (highest reviewer value)

1. Add `data/heldout_scan.json` (different domain, IDs, endpoints; ~5–8 findings).  
2. Tests:  
   - severity/count on held-out  
   - unseen endpoint  
   - unsupported existence → abstain  
   - multi-scan isolation  
   - **arbitrary IDs** (`SHIP-AUTH-01`, `web:xss:44`, `VULN_2026_91`) matched via catalog  
3. No hardcoded held-out answer packs in generator.

**Exit:** Evidence solution is not sample-only.

---

### Phase 3 — Planner boundary and validation

1. Add to existing plan schema only if needed: `in_scope: bool`, `execution: optional`.  
2. Update planner prompt: no final answer; no invented finding IDs; concepts for soft NL.  
3. Validate plan against scan catalog (endpoints, severities, IDs).  
4. Explicit structural filters **always override** planner.  
5. Tests: malformed planner, fake planner endpoint, fake planner IDs, conservative in_scope.  
6. Generator prompt: **theoretical risk ≠ scanner-reported finding** (existence).  
7. Catalog ID matching after scan load (not only `FINDING-\d+` regex).

**Exit:** Planner is constrained interpreter, not answer engine.

---

### Phase 4 — QueryService simplification (after 1–3 green)

Visible order in `query()` via **helpers** (extract, don’t replace wholesale):

```python
_build_route_and_plan(...)
_execute_structured_query(...)
_execute_semantic_query(...)
_generate_response(...)
_build_safe_response(...)
```

Flow:

```text
load scan → parse structure → exact path if confident
→ optional plan → validate/merge → filter or retrieve
→ abstain if unsupported → template or generate → citation gate
```

**Exit:** Code path matches diagram; tests still pass.

---

### Phase 5 — README and final demo (last)

Lead with:

> **Structured findings decide what exists. Hybrid retrieval resolves soft language. The LLM explains only verified findings.**

Include:

1. One architecture diagram (essay flow; no required scope-LLM box)  
2. 0 / 1 / 2 call budget  
3. Why SQLite + RAG  
4. Citations + abstention  
5. Held-out evaluation  
6. Known limitations  
7. Demo commands  

Rename defensive headings (e.g. “Did you game…?” → **Tradeoffs and evaluation approach**).  
Study guide may stay; README must be self-contained. **No score claims.**

Update `docs/STUDY_GUIDE_AND_JUSTIFICATION.md` lightly to match (no 9/10 claims).

---

## Architecture diagram (approved)

```text
Question + scan_id
  → Load selected scan + catalog
  → Extract explicit structure
  → Exact structured?
       Yes → SQLite FilterEngine → Structured template → Citation gate
       No  → Optional semantic planner
              → Validate against catalog
              → In scope / supported?
                   No  → Grounded refuse / abstain
                   Yes → BM25 + Dense → RRF
                        → Verify scan membership
                        → Knowledge (CWE/OWASP)
                        → Grounded generator (or row-bound fallback)
                        → Citation gate
  → Response
```

---

## File map (surgical)

| File | Work |
|------|------|
| `vector_store.py` | Fail-closed filters (P1) |
| `config.py`, `.env.example` | Defaults (P1) |
| `scope.py` / `query_service.py` | No default LLM scope (P1/P4) |
| `data/heldout_scan.json` | New (P2) |
| `tests/test_heldout_*.py`, isolation tests | P1–P2 |
| `plan_schema.py`, `planner.py`, `prompts.py` | Light fields + validation (P3) |
| `router.py` / query_service | Catalog IDs after load (P3) |
| `query_service.py` | Helper extraction (P4) |
| `README.md`, study guide | P5 last |

**Leave dead:** tool agent code optional/off; CE code optional via env.

---

## Definition of done

- [x] Filtered Chroma queries never drop isolation filters  
- [x] Defaults: no scope LLM, no tool agent, RRF light  
- [x] Held-out scan + isolation + arbitrary ID tests green  
- [x] Planner validates against catalog; explicit rules win  
- [x] Generator existence rule in prompt  
- [x] Query path readable as essay pipeline  
- [x] README matches code; no public score claims  
- [x] Full `pytest` green (push when ready)  

---

## Explicitly do not build

Frontend, K8s, Postgres, Redis, multi-tenant auth, agent as main path, more rerankers, web crawl, full schema rename rewrite, sample-query-specific branches, “9/10” marketing in README.

---

## Private score expectation (not for repo)

Full execution of this plan: **~8.7–9.0** take-home quality.  
Without held-out: lower.  
With code/README mismatch: lower.

---

*Implement only after exit_plan_mode user approval. Copy of this plan also lives at `docs/plan-v0.md` (update on implement start if needed).*
