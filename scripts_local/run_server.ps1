# Start the SSO decision PDP locally.
#   .\scripts_local\run_server.ps1            # real Jev (needs API_KEY_JEV)
#   .\scripts_local\run_server.ps1 -Mock      # offline rule-based signals
param(
    [switch]$Mock,
    [string]$Bind = "127.0.0.1:8080"
)
$ErrorActionPreference = "Stop"
$app = Join-Path $PSScriptRoot "..\app"

if ($Mock) { $env:SIGNAL_MODE = "mock" } else {
    $env:SIGNAL_MODE = "jev"
    if (-not $env:API_KEY_JEV) { throw "API_KEY_JEV is not set (or use -Mock)" }
}
$env:BIND_ADDR = $Bind
Push-Location $app
try { cargo run --release } finally { Pop-Location }
