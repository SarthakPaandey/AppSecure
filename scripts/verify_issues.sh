#!/usr/bin/env bash
# Re-run the 7 worst-offender questions to verify if issues still exist.
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
SCAN_ID="${SCAN_ID:-scan-20260324-001}"
SLEEP_SECS="${SLEEP_SECS:-1}"

query() {
  local label="$1"
  local q="$2"
  echo ""
  echo "======================================================================"
  echo "[$label] Q: $q"
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
    "answer": data.get("answer", "")[:1000],
}, indent=2))
PY
  sleep "$SLEEP_SECS"
}

echo "Issue verification against $BASE_URL (scan=$SCAN_ID)"

query "count" "How many CRITICAL findings are in the scan?"
query "top3" "What are the top 3 highest risk findings?"
query "negation" "Which findings are not authentication related?"
query "injection" "Which HIGH findings are injection problems?"
query "secrets" "Are there any secrets management findings?"
query "payments" "Which findings affect the payments endpoint and how severe are they?"
query "cwe918" "What is the remediation for CWE-918 in this scan?"

echo ""
echo "Done."
