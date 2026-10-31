#!/usr/bin/env bash
# Start the SSO decision PDP locally.
#   ./scripts_local/run_server.sh          # real Jev (needs API_KEY_JEV)
#   ./scripts_local/run_server.sh --mock   # offline rule-based signals
set -euo pipefail
cd "$(dirname "$0")/../app"

if [[ "${1:-}" == "--mock" ]]; then
  export SIGNAL_MODE=mock
else
  export SIGNAL_MODE=jev
  : "${API_KEY_JEV:?API_KEY_JEV is not set (or use --mock)}"
fi
export BIND_ADDR="${BIND_ADDR:-127.0.0.1:8080}"
exec cargo run --release
