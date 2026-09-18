# Start the JWT Audit Lab web app: FastAPI backend (:8000) + Vite UI (:5173).
# The backend opens in its own window; the UI (with proxy to the backend) runs
# here. Ctrl+C stops the UI and tears down the backend window.

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

Write-Host "Starting FastAPI backend on http://localhost:8001 ..." -ForegroundColor Cyan
$api = Start-Process -PassThru -WorkingDirectory (Join-Path $root "auditor") powershell `
    -ArgumentList '-NoExit', '-Command', 'uvicorn app:app --host 0.0.0.0 --port 8001 --reload'

Write-Host "Starting Vite UI on http://localhost:5173 ..." -ForegroundColor Cyan
Push-Location (Join-Path $root "auditor/static")
try {
    if (-not (Test-Path "node_modules")) {
        Write-Host "Installing UI dependencies (first run)..." -ForegroundColor Yellow
        npm install
    }
    npm run dev
}
finally {
    Pop-Location
    if ($api -and -not $api.HasExited) {
        Write-Host "Stopping backend..." -ForegroundColor Cyan
        Stop-Process -Id $api.Id -Force -ErrorAction SilentlyContinue
    }
}
