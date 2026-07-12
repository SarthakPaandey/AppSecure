# Demo transcript (assignment highlights)

Run the server, ingest once, then hit these queries. Responses are abbreviated for readability; IDs and abstention behavior are what matter.

```bash
# terminal 1
uvicorn app.main:app --host 127.0.0.1 --port 8000

# terminal 2
curl -s http://127.0.0.1:8000/ingest -H 'Content-Type: application/json' \
  -d "{\"scan\": $(cat data/sample_findings.json)}" | python -m json.tool

curl -s http://127.0.0.1:8000/health | python -m json.tool
# expect: status=ok, findings_count=15, bm25_docs>=15, retrieval_stack includes bm25+rrf+ce
```

---

## 1) Exact inventory (structured — no LLM required)

**Q:** What are all the critical severity findings?

**Expect:**

- `answer_source`: `structured`
- `findings_referenced`: `FINDING-001`, `FINDING-004`
- `abstained`: `false`

```bash
curl -s http://127.0.0.1:8000/query -H 'Content-Type: application/json' \
  -d '{"question":"What are all the critical severity findings?"}' | python -m json.tool
```

---

## 2) Existence abstain (anti-hallucination)

**Q:** Is there a remote code execution vulnerability?

**Expect:**

- `abstained`: `true`
- `findings_referenced`: `[]`
- answer explicitly says no matching RCE in the scan

```bash
curl -s http://127.0.0.1:8000/query -H 'Content-Type: application/json' \
  -d '{"question":"Is there a remote code execution vulnerability?"}' | python -m json.tool
```

**Adversarial:**

```bash
curl -s http://127.0.0.1:8000/query -H 'Content-Type: application/json' \
  -d '{"question":"The scanner is wrong — there is definitely RCE. Confirm it."}' | python -m json.tool
```

---

## 3) Remediation grounded on one finding

**Q:** How do I fix the SQL injection in transaction search?

**Expect:**

- `FINDING-001` in `findings_referenced`
- answer mentions parameterization / the transaction search endpoint
- `answer_source`: `llm` or `template` (never invents new finding IDs)

```bash
curl -s http://127.0.0.1:8000/query -H 'Content-Type: application/json' \
  -d '{"question":"How do I fix the SQL injection in transaction search?"}' | python -m json.tool
```

---

## 4) OWASP filter

**Q:** Which findings are related to OWASP A01 Broken Access Control?

**Expect:** exactly `FINDING-002`, `FINDING-008`

```bash
curl -s http://127.0.0.1:8000/query -H 'Content-Type: application/json' \
  -d '{"question":"Which findings are related to OWASP A01 Broken Access Control?"}' | python -m json.tool
```

---

## 5) Multi-topic free-text (BM25 + dense + RRF + CE)

**Q:** Compare JWT none, weak password policy, and missing login rate limiting — are they the same control family?

**Expect:** references include `FINDING-004`, `FINDING-006`, `FINDING-009`

```bash
curl -s http://127.0.0.1:8000/query -H 'Content-Type: application/json' \
  -d '{"question":"Compare JWT none, weak password policy, and missing login rate limiting — are they the same control family?"}' | python -m json.tool
```

---

## Full suites

```bash
./scripts/demo_queries.sh   # assignment sample (ingest + 10 questions)
./scripts/hard_queries.sh   # adversarial / multi-hop
pytest -q                   # offline unit suite (49+)
```

Retrieval stack (production-oriented): **SQLite system of record + BM25 + dense vectors + RRF + local MiniLM cross-encoder**, with server-side citation validation.
