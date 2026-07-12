# Validation record

Concise evidence for reviewers. **Not an SLA.** Latency is provider-dependent.

## Environment

| Item | Value |
|------|--------|
| Date (local) | 2026-07-13 |
| Host | macOS (Apple Silicon) |
| Python (clean venv) | 3.14.x via `python3 -m venv .venv-clean` |
| Package install | `pip install -r requirements.txt` (includes optional `sentence-transformers`) |
| Chat LLM | Cerebras OpenAI-compatible `gemma-4-31b` |
| Embeddings | ModelScope `Qwen/Qwen3-Embedding-8B` |
| Defaults | `USE_LLM_SCOPE_GATE=false`, `USE_TOOL_AGENT=false`, `RERANK_MODE=light`, `CROSS_ENCODER_ENABLED=false` |
| Fail-soft | `LLM_TIMEOUT_S=20`, `LLM_MAX_RETRIES=0`, `EMBED_TIMEOUT_S=10`, `EMBED_MAX_RETRIES=0` |

Keys live only in local `.env` (never committed). See `.env.example`.

## Commands used

### Clean offline suite

```bash
python3 -m venv .venv-clean
source .venv-clean/bin/activate   # Windows: .venv-clean\Scripts\activate
pip install -r requirements.txt
pytest -q
```

**Result:** `136 passed` (≈3s).

### Documented local run (from README)

```bash
cp .env.example .env   # fill MODELSCOPE_API_KEY + LLM_API_KEY
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

```bash
curl -s http://localhost:8000/health | python -m json.tool

curl -s http://localhost:8000/ingest \
  -H 'Content-Type: application/json' \
  -d "{\"scan\": $(cat data/sample_findings.json)}" | python -m json.tool

curl -s http://localhost:8000/query \
  -H 'Content-Type: application/json' \
  -d '{"question":"What are all the critical severity findings?"}' | python -m json.tool

curl -s http://localhost:8000/ingest \
  -H 'Content-Type: application/json' \
  -d "{\"scan\": $(cat data/heldout_scan.json)}" | python -m json.tool

curl -s http://localhost:8000/query \
  -H 'Content-Type: application/json' \
  -d '{"question":"How many CRITICAL findings?","scan_id":"scan-heldout-shipyard-2026"}' \
  | python -m json.tool

BASE_URL=http://127.0.0.1:8000 SCAN_ID=scan-20260324-001 \
  python scripts/live_validate.py
```

**README command check (this machine):** all of the above succeeded. JSON quoting with `$(cat data/…)` works under bash/zsh.

### Docker

```bash
cp .env.example .env   # fill keys
docker compose up --build
curl http://localhost:8000/health
```

**This run:** Docker CLI is installed (`Docker Compose v5.1.4`), but the **Docker daemon was not running** (`docker.sock` unavailable). Image build could not be completed here. Dockerfile copies `app/`, `data/knowledge/`, `data/sample_findings.json`, and `data/heldout_scan.json`. Compose mounts persistent SQLite + Chroma volumes and expects a filled `.env`.

---

## Offline results

```text
Offline (clean venv / current suite): 144 passed
```

Includes unit coverage for filters, citations, isolation, held-out IDs, planner policy, fail-soft LLM/embed paths, **specific subtype existence** (command injection ≠ SQLi), golden cases, and API smoke with fakes.

---

## Live correctness

```text
Live correctness (scripts/live_validate.py): 43/43 PASS
Live README smoke (sample CRITICAL + held-out count): OK
```

Latest measured suite metrics (one warm server run, dual-scan DB):

```text
pass_rate: 1.0
lat_p50:   ~579 ms
lat_p95:   ~1131 ms
wall_p95:  ~1.13 s
sources:   structured 28 | template 7 | abstain 7 | llm 1
```

Earlier post-fail-soft run (for comparison):

```text
lat_p50: ~381 ms
lat_p95: ~988 ms
```

**Disclaimer:** Latency is **provider-dependent**. These values represent **one measured run**, not a guaranteed SLA. Cold starts, ModelScope embed load, and Cerebras queueing can raise tails.

### Fail-soft / templates

Some soft explain/remediate/compare cases returned `answer_source=template` after LLM timeout or invalid JSON. That is **intentional fail-soft**:

- citations remain bound to retrieved finding IDs;
- the system does not hang multi-minute on a dead provider;
- inventory/SQL paths stay `structured` without needing the chat model.

---

## Held-out evaluation

| Check | Result |
|-------|--------|
| Ingest `data/heldout_scan.json` | OK (7 findings) |
| CRITICAL count on held-out | 3 IDs: `INV-SQL-12`, `SHIP-AUTH-01`, `SHIP-SSRF-07` |
| Catalog IDs (`SHIP-AUTH-01`, `web:xss:44`, `VULN_2026_91`) | Matched via catalog (unit + live) |
| Multi-scan isolation | Held-out CRITICAL query never returned `FINDING-*`; sample never returned held-out IDs |

---

## Paraphrase probes (no router changes)

Evaluated **without** adding sample-specific branches. Outcome is mixed by design—soft NL is not full NLU.

| Question | Scan | Observed |
|----------|------|----------|
| Could a warehouse employee retrieve another tenant’s invoice? | held-out | **OK** → `VULN_2026_91` |
| Are there findings on routes containing invoice? | held-out | **OK** → `VULN_2026_91` |
| Which issues involve user-controlled outbound requests? | sample | **Weak** — broad retrieval (includes non-SSRF); template narration |
| Do any endpoints permit horizontal privilege escalation? | sample | **Miss** — abstained (soft authZ paraphrase) |
| Show non-critical authentication weaknesses. | sample | **Weak** — did not cleanly surface 006/009/015 |

**No runtime change** for these misses: they are general soft-language limitations, not a one-line bug to special-case.

---

## Negation and absence probes

| Question | Observed |
|----------|----------|
| Show authentication findings that are not CRITICAL. | **OK** → `FINDING-006`, `015`, `009` |
| List A01 findings excluding document download. | **OK** → `FINDING-002` (008 excluded) |
| Is there XXE? | **OK** → abstain |
| Does the scan contain RCE, or only issues that could theoretically lead to it? | **OK** → abstain (existence) |
| Are there any command injection findings? | **Fixed** — specific subtype existence requires direct support (CWE-78 / command-injection wording). Parent “injection” family match is insufficient → **abstain** when absent |

Regression (offline): `tests/test_existence_subtype.py` — command injection absent abstains; SQL injection present → FINDING-001; broad “injection findings” listing may still return family members.

---

## Known limitations (honest)

1. **Soft NL / taxonomy heuristics** — curated topics and phrases; unusual paraphrases can miss or over-retrieve.  
2. **Orchestrator** — modularized, still centralized vs ideal micro-pipeline.  
3. **Provider variance** — embed/LLM latency and fail-soft template rate vary by network and quotas.  
4. **Docker** — documented; daemon must be running locally to verify compose.  
5. **Not production multi-tenant** — no auth, audit, or row-level tenancy product.

---

## Design answers (short)

### Why SQLite and Chroma?

SQLite guarantees complete and exact inventory operations. Chroma handles semantic retrieval. They solve different problems.

### Why BM25 and dense retrieval?

Security questions mix exact paths, CWE IDs, and acronyms with semantic paraphrases. BM25 handles exact terms; dense retrieval handles meaning; RRF combines them simply.

### Why rules and an LLM planner?

Rules handle explicit high-confidence operators. The planner handles ambiguous natural language. Planner output is validated against the scan catalog before execution; explicit rules win on conflicts.

### How do you prevent hallucinations?

The scan store determines what exists; unsupported existence queries abstain; every finding citation is validated against retrieved rows for the selected `scan_id`. Vector filters fail closed. LLM/embed failures degrade to store-bound templates, not invented rows.

### What is hacky?

The taxonomy and intent rules are curated; the orchestrator remains more centralized than ideal; provider performance varies. Soft paraphrases (e.g. “horizontal privilege escalation”, pure “command injection”) are imperfect. A production version would add broader evaluation, tenant controls, observability, and versioned ingestion.

---

## Submission hygiene (checked)

| Check | Result |
|-------|--------|
| `.env` gitignored / not tracked | Yes |
| `data/chroma/`, `*.db` ignored | Yes |
| `server.log` ignored | Yes |
| `.venv` / `.venv-clean` ignored | Yes |
| `git ls-files` secrets scan | No API keys / private env tracked |
| `data/query_validation_report.json` | Fictional finding IDs only; no live keys |

Generated clean venv `.venv-clean/` is local-only (gitignored); remove with `rm -rf .venv-clean` after review if desired.
