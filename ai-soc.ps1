# ─────────────────────────────────────────────────────────────────────────────
# AI-SOC Deploy Script for Windows (PowerShell)
# ─────────────────────────────────────────────────────────────────────────────
# Usage:
#   .\ai-soc.ps1              # Deploy and start
#   .\ai-soc.ps1 -ResetDb     # Wipe database and start fresh
#   .\ai-soc.ps1 -StartAgent  # Also start the log agent after deploy
# ─────────────────────────────────────────────────────────────────────────────

param(
    [switch]$ResetDb,
    [switch]$StartAgent
)

$ErrorActionPreference = "Stop"

# ── Colors ───────────────────────────────────────────────────────────────────
function Info  { Write-Host "[AI-SOC] $args" -ForegroundColor Cyan }
function Ok    { Write-Host "[✓] $args"       -ForegroundColor Green }
function Warn  { Write-Host "[!] $args"       -ForegroundColor Yellow }
function Err   { Write-Host "[✗] $args"       -ForegroundColor Red; exit 1 }

# ── Check Docker Desktop is running ──────────────────────────────────────────
Info "Checking Docker..."
try {
    docker info 2>&1 | Out-Null
    Ok "Docker is running"
} catch {
    Err "Docker Desktop is not running. Start it and try again."
}

# ── Create .env if missing ───────────────────────────────────────────────────
if (-not (Test-Path ".env")) {
    Info "Creating .env from .env.example..."
    Copy-Item ".env.example" ".env"
    Warn ".env created — review passwords before going to production"
}

# ── Auto-generate secrets ─────────────────────────────────────────────────────
function New-Secret([int]$Bytes = 32) {
    $arr = [byte[]]::new($Bytes)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($arr)
    return ($arr | ForEach-Object { $_.ToString("x2") }) -join ""
}

$envContent = Get-Content ".env" -Raw

if ($envContent -match "CHANGE_ME_generate_with_openssl_rand_hex_32") {
    $key = New-Secret 32
    $envContent = $envContent -replace "CHANGE_ME_generate_with_openssl_rand_hex_32", $key
    Ok "SECRET_KEY auto-generated"
}

if ($envContent -match "CHANGE_ME_generate_with_openssl_rand_hex_24") {
    $apiKey = New-Secret 24
    $envContent = $envContent -replace "CHANGE_ME_generate_with_openssl_rand_hex_24", $apiKey
    Ok "API_KEY auto-generated"
}

if ($envContent -match "CHANGE_DB_PASSWORD") {
    $dbPass = New-Secret 12
    $envContent = $envContent -replace "CHANGE_DB_PASSWORD", $dbPass
    Ok "DB_PASSWORD auto-generated"
}

Set-Content ".env" $envContent

# ── Optional DB reset ─────────────────────────────────────────────────────────
if ($ResetDb) {
    Warn "Wiping PostgreSQL volume..."
    docker compose down -v 2>&1 | Out-Null
    Ok "Volume wiped"
}

# ── Start the stack ───────────────────────────────────────────────────────────
Info "Starting AI-SOC containers..."
docker compose up -d

# ── Wait for health ───────────────────────────────────────────────────────────
Info "Waiting for backend to become healthy..."
$maxWait = 120
$elapsed = 0
$healthy = $false

while ($elapsed -lt $maxWait) {
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:8000/health" -TimeoutSec 3
        $healthy = $true
        break
    } catch {
        Start-Sleep -Seconds 3
        $elapsed += 3
        Write-Host -NoNewline "."
    }
}
Write-Host ""

if (-not $healthy) {
    Err "Backend did not become healthy within ${maxWait}s. Run: docker compose logs app"
}
Ok "Backend is healthy ($elapsed s)"

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  AI-SOC is running!" -ForegroundColor Green
Write-Host "════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "  🖥️  Dashboard    → " -NoNewline; Write-Host "http://localhost:3000" -ForegroundColor Cyan
Write-Host "  🔌  Backend API  → " -NoNewline; Write-Host "http://localhost:8000" -ForegroundColor Cyan
Write-Host "  📚  Swagger Docs → " -NoNewline; Write-Host "http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host "  ❤️  Health Check → " -NoNewline; Write-Host "http://localhost:8000/health" -ForegroundColor Cyan
Write-Host ""
Write-Host "  🔑  Login: POST http://localhost:8000/auth/login" -ForegroundColor White
Write-Host '      Body: {"username": "admin", "password": "<ADMIN_PASSWORD from .env>"}' -ForegroundColor Gray
Write-Host ""
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
Write-Host ""
Warn "To view logs:  docker compose logs -f app"
Warn "To stop:       docker compose down"
Write-Host ""

# ── Optionally start the native Windows log agent ─────────────────────────────
if ($StartAgent) {
    Info "Starting Windows log agent in a new window..."
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "python log_agent.py" -WorkingDirectory (Get-Location)
    Ok "Log agent started (reads Windows Event Log + Firewall log)"
} else {
    Write-Host "  📋  To start the log agent (reads Windows Event Log):" -ForegroundColor Yellow
    Write-Host "      pip install -r requirements-agent.txt" -ForegroundColor Gray
    Write-Host "      python log_agent.py" -ForegroundColor Gray
    Write-Host ""
}
