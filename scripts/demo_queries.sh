#!/usr/bin/env bash
# Demo: ingest sample findings and run assignment sample queries.
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Health"
curl -sS "$BASE_URL/health" | python3 -m json.tool

echo "==> Ingest"
python3 - <<PY
import json, urllib.request
scan = json.load(open("$ROOT/data/sample_findings.json"))
body = json.dumps({"scan": scan}).encode()
req = urllib.request.Request(
    "$BASE_URL/ingest",
    data=body,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req) as resp:
    print(resp.read().decode())
PY

QUESTIONS=(
  "What are all the critical severity findings?"
  "Explain the IDOR vulnerability on the accounts endpoint."
  "How do I fix the SQL injection in transaction search?"
  "Which findings are related to OWASP A01 Broken Access Control?"
  "Is there a remote code execution vulnerability?"
  "What authentication issues were found?"
  "Give me a summary of all findings sorted by severity."
  "What's the risk of the SSRF finding and how could an attacker exploit it?"
  "Are there any findings related to the payments endpoint?"
  "Compare the two IDOR findings — are they the same root cause?"
)

i=1
for q in "${QUESTIONS[@]}"; do
  echo ""
  echo "==> Query $i: $q"
  python3 - <<PY
import json, urllib.request
body = json.dumps({"question": """$q"""}).encode()
req = urllib.request.Request(
    "$BASE_URL/query",
    data=body,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=120) as resp:
    data = json.loads(resp.read().decode())
print(json.dumps({
    "intent": data.get("query_intent"),
    "abstained": data.get("abstained"),
    "findings_referenced": data.get("findings_referenced"),
    "latency_ms": data.get("latency_ms"),
    "answer": data.get("answer", "")[:800],
    "citations": data.get("citations"),
}, indent=2))
PY
  i=$((i+1))
done

echo ""
echo "Done."
