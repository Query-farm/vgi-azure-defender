#!/bin/sh
# Dispatch this VGI worker image into one of its transports:
#   http   (default) HTTP server on $PORT (scripts/serve.ts: /health + VGI RPC)
#   stdio            a worker DuckDB spawns over stdio (on-host execution)
#   *                exec'd verbatim (debug escape hatch)
set -e
case "${1:-http}" in
  http)  exec bun run scripts/serve.ts ;;
  stdio) shift 2>/dev/null || true; exec bun run src/worker.ts "$@" ;;
  *)     exec "$@" ;;
esac
