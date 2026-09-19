# Manual protocol probe

`scripts/probe_proxy.mjs` uses only Node.js built-ins and is independent of the
Rust transport helpers. It connects to an already running TGLock listener at
`127.0.0.1`, sends one unauthenticated `req_pq_multi` through a secret-protected
obfuscated2 padded-intermediate stream, and validates the returned `resPQ`, its
request nonce, and the lengths of its TL fields. It stops before creating an
authorization key. No Telegram account, API ID, API hash or login is needed.

The secret is read from an explicitly supplied file and is never printed. Use
the same secret file as the running CLI. Do not paste proxy links or secret
values into public logs.

```sh
# Offline validation first: no network access.
node scripts/probe_proxy.mjs --self-test

# Start a local CLI separately, using a persistent secret file.
tglock-cli --port 18080 --secret-file /private/path/tglock-secret

# Ordinary DC, media route, and CDN route; run each explicitly.
node scripts/probe_proxy.mjs --port 18080 --secret-file /private/path/tglock-secret --dc 2
node scripts/probe_proxy.mjs --port 18080 --secret-file /private/path/tglock-secret --dc -4 --fragment-size 7
node scripts/probe_proxy.mjs --port 18080 --secret-file /private/path/tglock-secret --dc 203
```

On Windows, supply the downloaded CLI executable and a Windows file path in the
same commands. Supported DC values are `1` through `5` and `203`; a negative
value requests a media route. `--timeout-ms` defaults to 15000 and is bounded at
120000. The response is bounded at 2 MiB. `--fragment-size 7` sends small writes
with 2 ms gaps to exercise stream fragmentation; TCP can still combine writes.

A successful JSON report contains `response: "resPQ"`, `nonceMatches: true`, the
requested DC, the public RSA fingerprint count, and elapsed time. Exit status 1
means connection, timeout, decryption/framing or response validation failed.
The ordinary CI suite does not run this live probe.

Success demonstrates a correctly relayed protocol exchange. It does **not**
authenticate the responding server, prove its DC identity, log into an account,
or verify message sending, media downloads or Android lifecycle. In particular,
`requestedDc` describes the request, not an independently confirmed backend.

## Isolate CDN transport failures

To distinguish an unavailable CDN WebSocket endpoint from an unavailable CDN
TCP connection, explicitly run:

```sh
node scripts/probe_proxy.mjs --direct-cdn --dc 203
```

This optional mode bypasses local TGLock and connects **only** to the pinned
Telegram CDN address `91.105.192.100:443`, using raw obfuscated2 TCP without a
proxy secret or TLS. It supports no arbitrary host. It performs the same single
unauthenticated exchange and still does not prove account or media operation.
The parser accepts trailing bytes after the complete `resPQ` TL object because
live CDN replies can include random padding in the declared message length.

Protocol references: [handshake initiation](https://core.telegram.org/mtproto/auth_key),
[obfuscated transports](https://core.telegram.org/mtproto/mtproto-transports),
and [unencrypted messages](https://core.telegram.org/mtproto/description#unencrypted-message).
