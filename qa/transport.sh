#!/usr/bin/env bash
set -euo pipefail
temp="$RUNNER_TEMP/tglock-transport"
mkdir -p "$temp"
export WRANGLER_SEND_METRICS=false CI=true
npm install --prefix "$temp" --no-audit --no-fund --silent wrangler@4.166.0
for n in 15 22; do
  p=$((18800+n))
  git show "v2.0.0-beta.$n:worker/tglock-worker.js" > "$temp/worker.mjs"
  sha256sum "$temp/worker.mjs"
  "$temp/node_modules/.bin/wrangler" dev "$temp/worker.mjs" --local --ip 127.0.0.1 --port "$p" --compatibility-date 2026-07-01 >"$temp/wrangler-$n.log" 2>&1 & child=$!
  trap 'kill "$child" 2>/dev/null || true' EXIT
  ready=0
  for i in {1..100}; do
    if [ "$(curl --max-time 1 -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/apiws" || true)" = 426 ]; then ready=1; break; fi
    sleep .25
  done
  cat "$temp/wrangler-$n.log"
  test "$ready" = 1
  node qa/exercise-worker.mjs "$p" "$n" "$temp"
  kill "$child" 2>/dev/null || true; wait "$child" || true
  trap - EXIT
done
