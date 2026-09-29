#!/usr/bin/env sh
# Esempio completo in simulazione (Linux/macOS). Nessuna VM necessaria.
set -e
OUT="${1:-./out}"
webcquisition -c examples/dry-run.yaml acquire CASE-DEMO-001 --output "$OUT/CASE-DEMO-001" --dry-run --auto-stop 3 || true
webcquisition verify --output "$OUT/CASE-DEMO-001"
echo "Report: $OUT/CASE-DEMO-001/report/acquisition-report.html"
