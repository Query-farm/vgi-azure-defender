#!/usr/bin/env bash
# Typecheck OWN sources only. The @query-farm arrow ecosystem ships .ts source
# whose type errors skipLibCheck cannot skip (skipLibCheck only skips .d.ts); those
# node_modules-source errors are external. Fails only on errors in THIS repo's src/.
set -uo pipefail
errs="$(tsc --noEmit --pretty false 2>&1 | grep 'error TS' | grep -v node_modules || true)"
if [ -n "$errs" ]; then
  printf '%s\n' "$errs"
  echo "typecheck FAILED (own sources)"
  exit 1
fi
echo "typecheck clean (own sources)"
