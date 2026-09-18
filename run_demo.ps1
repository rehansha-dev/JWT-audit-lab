# JWT Audit Lab - Live Demo (PowerShell)
# Boots both target servers, audits each, writes JSON reports, then stops the servers.
# Prereq: the auditor must be installed (Set-Location auditor; pip install -e .).

$root = $PSScriptRoot

Write-Host ""
Write-Host "=============================================="
Write-Host "        JWT Audit Lab - Live Demo"
Write-Host "=============================================="
Write-Host ""

# Start both servers as background node processes (tracked by PID for clean shutdown).
# server.js auto-generates its dev RSA keypair on load, so no separate genkeys step.
$vuln = Start-Process node -ArgumentList "src/server.js" `
    -WorkingDirectory "$root\targets\vulnerable-server" -PassThru -WindowStyle Hidden
$secure = Start-Process node -ArgumentList "src/server.js" `
    -WorkingDirectory "$root\targets\secure-server" -PassThru -WindowStyle Hidden

try {
    Write-Host "Starting servers (vulnerable :4000, secure :4001)..."
    Start-Sleep -Seconds 3

    Set-Location "$root\auditor"

    Write-Host ""
    Write-Host "--- Auditing VULNERABLE server (http://localhost:4000) ---"
    Write-Host ""
    jwtaudit audit --base-url http://localhost:4000 --json-out "$root\vulnerable-report.json"

    Write-Host ""
    Write-Host "----------------------------------------------"
    Write-Host ""
    Write-Host "--- Auditing SECURE server (http://localhost:4001) ---"
    Write-Host ""
    jwtaudit audit --base-url http://localhost:4001 --json-out "$root\secure-report.json"

    Write-Host ""
    Write-Host "Demo complete. Reports: vulnerable-report.json, secure-report.json"
}
finally {
    # Stop the exact server processes we started (clean shutdown).
    if ($vuln)   { Stop-Process -Id $vuln.Id   -Force -ErrorAction SilentlyContinue }
    if ($secure) { Stop-Process -Id $secure.Id -Force -ErrorAction SilentlyContinue }
}
