#!/usr/bin/env bash
# Extra adversarial / edge-case questions for the Vulnerability Explainer API.
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
SCAN_ID="${SCAN_ID:-scan-20260324-001}"
SLEEP_SECS="${SLEEP_SECS:-1}"

query() {
  local q="$1"
  echo ""
  echo "======================================================================"
  echo "Q: $q"
  echo "----------------------------------------------------------------------"
  python3 - <<PY
import json, urllib.request, time
body = json.dumps({
    "question": """$q""",
    "scan_id": "$SCAN_ID",
}).encode()
req = urllib.request.Request(
    "$BASE_URL/query",
    data=body,
    headers={"Content-Type": "application/json"},
    method="POST",
)
t0 = time.time()
try:
    with urllib.request.urlopen(req, timeout=180) as resp:
        data = json.loads(resp.read().decode())
except urllib.error.HTTPError as e:
    data = json.loads(e.read().decode())
wall = round(time.time() - t0, 2)
print(json.dumps({
    "intent": data.get("query_intent"),
    "abstained": data.get("abstained"),
    "findings_referenced": data.get("findings_referenced"),
    "latency_ms": data.get("latency_ms"),
    "wall_s": wall,
    "answer": data.get("answer", "")[:900],
}, indent=2))
PY
  sleep "$SLEEP_SECS"
}

echo "Extra query suite against $BASE_URL (scan=$SCAN_ID)"

# Numeric constraint / ranking
query "What are the top 3 highest risk findings?"
query "Rank the top 3 findings by fintech risk and explain why each matters."
query "How would you fix the top 3 findings before production go-live?"
query "What is the single most severe finding and why?"
query "How many CRITICAL findings are in the scan?"

# Classification accuracy
query "Which HIGH findings are injection problems?"
query "Which findings are authentication problems?"
query "Which findings are not authentication related?"

# SSRF / cloud credentials reasoning
query "Is SSRF in this scan a cloud credential threat? Explain with evidence."
query "What is the remediation for CWE-918 in this scan?"

# PII / financial data leak broadening
query "What findings could lead to data breach of customer financial records?"
query "Which findings could leak other customers' PII?"

# Multi-topic compare / chaining
query "Compare SQL injection and SSRF — are they the same type of vulnerability?"
query "Can chaining SQLi and IDOR lead to account takeover?"
query "What is the difference between FINDING-002 and FINDING-008?"

# Specific / endpoint / class
query "Is there a JWT vulnerability? If yes, what is the exact parameter and correct fix?"
query "List all findings that are both HIGH severity and CWE-639."
query "Which findings affect the payments endpoint and how severe are they?"
query "Is there a finding on /graphql?"
query "Are there any secrets management findings?"

echo ""
echo "Done."
