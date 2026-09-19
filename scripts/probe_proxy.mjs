#!/usr/bin/env node
// Manual, account-free probe of an ALREADY RUNNING local TGLock instance.
// Protocol sources (this does not import the Rust implementation):
// https://core.telegram.org/mtproto/auth_key
// https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation
// https://core.telegram.org/mtproto/description#unencrypted-message
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createConnection } from "node:net";
import { setTimeout as sleep } from "node:timers/promises";
import assert from "node:assert/strict";

const MAX_RESPONSE = 2 * 1024 * 1024;
const HELP = `Usage: node scripts/probe_proxy.mjs --secret-file PATH [--port 1080] [--dc 2] [--timeout-ms 15000] [--fragment-size 0]
Or: node scripts/probe_proxy.mjs --direct-cdn --dc 203
DC: 1..5 or 203; negative values request the media route.
Default connects only to 127.0.0.1. --direct-cdn explicitly probes only 91.105.192.100:443 without a secret.
Reads the local proxy secret from the explicit file; never prints it.
Sends one req_pq_multi and checks resPQ/nonce. No account, API credentials, login or auth key is created.
This proves a protocol response, not DC identity, account operation or media downloads.
Use --self-test for offline parser checks; --fragment-size 7 sends small writes with 2ms gaps.`;

function options(args) {
  const result = { port: 1080, dc: 2, timeoutMs: 15000, fragmentSize: 0 };
  const numeric = { "--port": "port", "--dc": "dc", "--timeout-ms": "timeoutMs", "--fragment-size": "fragmentSize" };
  for (let i = 0; i < args.length; i++) {
    const name = args[i];
    if (name === "--direct-cdn") { result.directCdn = true; continue; }
    const value = args[++i];
    if (value === undefined) throw new Error(`Missing value for ${name}`);
    if (name === "--secret-file") result.secretFile = value;
    else if (numeric[name] && /^-?\d+$/.test(value)) result[numeric[name]] = Number(value);
    else throw new Error(`Invalid option ${name}`);
  }
  if (!result.secretFile && !result.directCdn) throw new Error("--secret-file is required");
  if (result.directCdn && result.dc !== 203) throw new Error("Direct CDN probe requires --dc 203");
  if (!Number.isInteger(result.port) || result.port < 1 || result.port > 65535) throw new Error("Invalid port");
  if (![1, 2, 3, 4, 5, 203].includes(Math.abs(result.dc))) throw new Error("Unsupported DC");
  if (result.timeoutMs < 100 || result.timeoutMs > 120000) throw new Error("Timeout must be 100..120000ms");
  if (result.fragmentSize < 0 || result.fragmentSize > 65536) throw new Error("Fragment size must be 0..65536");
  return result;
}

function makeRequest(secret, dc) {
  let header;
  do {
    header = randomBytes(64);
  } while (header[0] === 0xef || ["HEAD", "POST", "GET ", "OPTI"].includes(header.toString("ascii", 0, 4))
    || [0xeeeeeeee, 0xdddddddd, 0x02010316].includes(header.readUInt32LE()) || header.readUInt32LE(4) === 0);
  header.fill(0xdd, 56, 60); // padded intermediate transport
  header.writeInt16LE(dc, 60);
  const salted = (key) => secret ? createHash("sha256").update(key).update(secret).digest() : Buffer.from(key);
  const encrypt = createCipheriv("aes-256-ctr", salted(header.subarray(8, 40)), header.subarray(40, 56));
  const reversed = Buffer.from(header.subarray(8, 56)).reverse();
  const decrypt = createDecipheriv("aes-256-ctr", salted(reversed.subarray(0, 32)), reversed.subarray(32));
  const wireHeader = Buffer.from(header);
  encrypt.update(header).copy(wireHeader, 56, 56); // advances outgoing CTR by all 64 bytes

  const nonce = randomBytes(16);
  const payload = Buffer.alloc(40);
  // auth_key_id = 0, client message ID divisible by four, TL payload length = 20.
  const now = BigInt(Date.now());
  const messageId = ((now / 1000n << 32n) | ((now % 1000n) * (1n << 32n) / 1000n)) & ~3n;
  payload.writeBigUInt64LE(messageId, 8);
  payload.writeUInt32LE(20, 16);
  payload.writeUInt32LE(0xbe7e8ef1, 20);
  nonce.copy(payload, 24);
  const padded = Buffer.concat([payload, randomBytes(7)]);
  const length = Buffer.alloc(4);
  length.writeUInt32LE(padded.length);
  return { wire: Buffer.concat([wireHeader, encrypt.update(Buffer.concat([length, padded]))]), decrypt, nonce };
}

function parseResPQ(frame, nonce) {
  if (frame.length === 4) throw new Error(`MTProto transport error ${frame.readInt32LE()}`);
  if (frame.length < 20 || frame.readBigUInt64LE() !== 0n) throw new Error("Expected an unencrypted MTProto response");
  const length = frame.readUInt32LE(16);
  if (length < 48 || length % 4 !== 0 || length > frame.length - 20) throw new Error("Invalid MTProto message length");
  const body = frame.subarray(20, 20 + length);
  if (body.readUInt32LE() !== 0x05162463) throw new Error("Response is not resPQ");
  if (!body.subarray(4, 20).equals(nonce)) throw new Error("resPQ nonce does not match request");
  // pq is at most eight bytes for this handshake, so its TL string uses the
  // one-byte length encoding followed by padding to a four-byte boundary.
  const pqLength = body[36];
  if (pqLength < 1 || pqLength > 8) throw new Error("Invalid resPQ pq length");
  const vectorOffset = 36 + Math.ceil((1 + pqLength) / 4) * 4;
  if (vectorOffset + 8 > body.length || body.readUInt32LE(vectorOffset) !== 0x1cb5c415) throw new Error("Invalid RSA fingerprint vector");
  const count = body.readUInt32LE(vectorOffset + 4);
  // A CDN may include trailing random bytes in its declared message length.
  // Validate the complete TL object fits; do not mistake padding for corruption.
  if (count < 1 || count > 64 || vectorOffset + 8 + count * 8 > body.length) throw new Error("Invalid RSA fingerprint count");
  // Deliberately do not infer DC identity from these public fingerprints.
  return { response: "resPQ", nonceMatches: true, rsaFingerprintCount: count };
}

async function probe(config) {
  let secret = null;
  if (!config.directCdn) {
    let hex = (await readFile(config.secretFile, "utf8")).trim();
    if (/^dd[0-9a-f]{32}$/i.test(hex)) hex = hex.slice(2);
    if (!/^[0-9a-f]{32}$/i.test(hex)) throw new Error("Secret file must contain 32 hex characters or dd followed by 32 hex characters");
    secret = Buffer.from(hex, "hex");
  }
  const { wire, decrypt, nonce } = makeRequest(secret, config.dc);
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const socket = createConnection(config.directCdn
      ? { host: "91.105.192.100", port: 443 }
      : { host: "127.0.0.1", port: config.port });
    let pending = Buffer.alloc(0);
    let received = 0;
    let finished = false;
    const finish = (error, result) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve({ transport: config.directCdn ? "direct-cdn-tcp" : "local-proxy", requestedDc: config.dc, ...result, elapsedMs: Date.now() - started });
    };
    const timer = setTimeout(() => finish(new Error("Timed out waiting for resPQ")), config.timeoutMs);
    socket.on("error", (error) => finish(error));
    socket.on("end", () => finish(new Error("Proxy closed before a complete resPQ response")));
    socket.on("data", (chunk) => {
      try {
        received += chunk.length;
        if (received > MAX_RESPONSE) throw new Error("Response exceeded the 2MiB limit");
        pending = Buffer.concat([pending, decrypt.update(chunk)]);
        while (pending.length >= 4) {
          const length = pending.readUInt32LE();
          if (length & 0x80000000) { // optional intermediate quick acknowledgment
            pending = pending.subarray(4);
            continue;
          }
          if (length < 4 || length > MAX_RESPONSE - 4) throw new Error("Invalid intermediate frame length");
          if (pending.length < 4 + length) return;
          if (length >= 8 && length <= 16 && pending.readUInt32LE(4) === 0xffffffff) {
            pending = pending.subarray(4 + length); // padded intermediate quick ACK
            continue;
          }
          finish(null, parseResPQ(pending.subarray(4, 4 + length), nonce));
          return;
        }
      } catch (error) { finish(error); }
    });
    socket.on("connect", async () => {
      try {
        socket.setNoDelay(true);
        const size = config.fragmentSize || wire.length;
        for (let offset = 0; offset < wire.length && !finished; offset += size) {
          socket.write(wire.subarray(offset, offset + size));
          if (config.fragmentSize) await sleep(2);
        }
      } catch (error) { finish(error); }
    });
  });
}

function selfTest() {
  // Fixed TL fixture: resPQ, request nonce 00..0f, server nonce 10..1f,
  // eight-byte pq, a one-element vector of public RSA fingerprints.
  const body = Buffer.from("63241605000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f08112233445566778800000015c4b51c010000008877665544332211", "hex");
  const envelope = Buffer.alloc(20);
  envelope.writeUInt32LE(body.length, 16);
  const frame = Buffer.concat([envelope, body, Buffer.from([1, 2, 3])]);
  const nonce = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
  assert.equal(parseResPQ(frame, nonce).rsaFingerprintCount, 1);
  const paddedEnvelope = Buffer.from(envelope);
  paddedEnvelope.writeUInt32LE(body.length + 128, 16);
  assert.equal(parseResPQ(Buffer.concat([paddedEnvelope, body, Buffer.alloc(128, 0x42)]), nonce).rsaFingerprintCount, 1);
  assert.throws(() => parseResPQ(frame, Buffer.alloc(16)), /nonce/);
  assert.throws(() => parseResPQ(frame.subarray(0, 30), nonce), /length/);
  const wrongConstructor = Buffer.from(frame);
  wrongConstructor[20] = 0;
  assert.throws(() => parseResPQ(wrongConstructor, nonce), /not resPQ/);
  const oversizedVector = Buffer.from(frame);
  oversizedVector.writeUInt32LE(65, 72);
  assert.throws(() => parseResPQ(oversizedVector, nonce), /count/);
  assert.throws(() => parseResPQ(Buffer.from("6cfeffff", "hex"), nonce), /-404/);
  console.log("Offline parser checks passed; no network connection made.");
}

try {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--self-test") selfTest();
  else if (args.length === 1 && ["--help", "-h"].includes(args[0])) console.log(HELP);
  else console.log(JSON.stringify(await probe(options(args)), null, 2));
} catch (error) {
  console.error(`Probe failed: ${error.message}`);
  process.exitCode = 1;
}
