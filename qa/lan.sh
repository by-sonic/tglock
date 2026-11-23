#!/usr/bin/env bash
set -euo pipefail
cli=tglock-cli-x86_64-unknown-linux-gnu
gh release download v2.0.0-beta.22 -p "$cli"
digest=$(gh release view v2.0.0-beta.22 --json assets --jq ".assets[]|select(.name==\"$cli\")|.digest")
echo "${digest#sha256:}  $cli" | sha256sum --check
chmod +x "$cli"
sudo ip netns add tgclient
sudo ip link add tgserver type veth peer name tgdevice
sudo ip link set tgdevice netns tgclient
sudo ip addr add 192.0.2.1/30 dev tgserver
sudo ip link set tgserver up
sudo ip -n tgclient addr add 192.0.2.2/30 dev tgdevice
sudo ip -n tgclient link set tgdevice up
sudo ip -n tgclient link set lo up
sudo ip -n tgclient route
umask 077
temp="$RUNNER_TEMP"
secret="$temp/tglock-lan.secret"
"./$cli" --bind 192.0.2.1 --port 18327 --secret-file "$secret" >"$temp/tglock-lan-private.log" 2>&1 & child=$!
trap 'kill "$child" 2>/dev/null || true' EXIT
for i in {1..50}; do [ -s "$secret" ] && break; sleep .1; done
test -s "$secret"
# Only substitute the local transport address. The protocol verifier, nonce
# and signed ordinary/media DC checks are byte-for-byte the project code.
python - "$temp/lan-probe.mjs" <<'PY'
import pathlib,sys
source=pathlib.Path('scripts/probe_proxy.mjs').read_text()
old='{ host: "127.0.0.1", port: config.port }'
assert source.count(old)==1
pathlib.Path(sys.argv[1]).write_text(source.replace(old, '{ host: "192.0.2.1", port: config.port }'))
PY
for dc in 2 -2 203; do
  sudo ip netns exec tgclient "$(which node)" "$temp/lan-probe.mjs" --port 18327 --secret-file "$secret" --batched --dc "$dc" --timeout-ms 18000
done
