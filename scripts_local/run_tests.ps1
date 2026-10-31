# Unit + integration tests, coverage, lint, audit and Playwright E2E.
#   .\scripts_local\run_tests.ps1          # everything offline (mock Jev)
#   .\scripts_local\run_tests.ps1 -Live    # also hit the real Jev API
param([switch]$Live)
$ErrorActionPreference = "Stop"
$root = Join-Path $PSScriptRoot ".."

Push-Location (Join-Path $root "app")
try {
    cargo fmt --check; if (-not $?) { throw "fmt" }
    cargo clippy --all-targets -- -W clippy::pedantic; if (-not $?) { throw "clippy" }
    cargo llvm-cov --html --output-dir ../docs/coverage; if (-not $?) { throw "tests" }
    cargo audit; if (-not $?) { throw "audit" }
    if ($Live) { cargo test --test integration -- --ignored --nocapture; if (-not $?) { throw "live" } }
} finally { Pop-Location }

Push-Location (Join-Path $root "e2e")
try {
    npm ci
    if ($Live) { $env:E2E_SIGNAL_MODE = "jev" } else { $env:E2E_SIGNAL_MODE = "mock" }
    npx playwright test; if (-not $?) { throw "e2e" }
} finally { Pop-Location }
