#!/usr/bin/env bash
# Unit + integration tests, coverage, lint, audit and Playwright E2E.
#   ./scripts_local/run_tests.sh          # everything offline (mock Jev)
#   ./scripts_local/run_tests.sh --live   # also hit the real Jev API
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
live="${1:-}"

cd "$root/app"
cargo fmt --check
cargo clippy --all-targets -- -W clippy::pedantic
cargo llvm-cov --html --output-dir ../docs/coverage
cargo audit
if [[ "$live" == "--live" ]]; then cargo test --test integration -- --ignored --nocapture; fi

cd "$root/e2e"
npm ci
E2E_SIGNAL_MODE=$([[ "$live" == "--live" ]] && echo jev || echo mock) npx playwright test
