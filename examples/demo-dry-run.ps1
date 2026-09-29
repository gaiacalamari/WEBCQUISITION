# Esempio completo in simulazione (Windows PowerShell). Nessuna VM necessaria.
param([string]$Out = ".\out")
webcquisition -c examples\dry-run.yaml acquire CASE-DEMO-001 --output "$Out\CASE-DEMO-001" --dry-run --auto-stop 3
webcquisition verify --output "$Out\CASE-DEMO-001"
Write-Host "Report: $Out\CASE-DEMO-001\report\acquisition-report.html"
