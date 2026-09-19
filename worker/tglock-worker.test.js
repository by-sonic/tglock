import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("./tglock-worker.js", import.meta.url), "utf8");
const tick = () => new Promise((resolve) => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((a, b) => { resolve = a; reject = b; });
  return { promise, resolve, reject };
}

// Execute the actual standalone deployment file, replacing only Cloudflare's
// platform primitives. No test-only implementation of the relay is used.
async function fixture({ opened = Promise.resolve(), write, timeout = false } = {}) {
  let readController;
  const readable = new ReadableStream({ start(controller) { readController = controller; } });
  const reads = { reject(error) { readController.error(error); } };
  const closed = deferred();
  const writes = [];
  const events = new Map();
  const state = { connects: 0, accepted: false, socketCloses: 0, sent: [], closes: [] };
  const server = {
    accept() { state.accepted = true; },
    addEventListener(name, callback) { events.set(name, callback); },
    close(code, reason) { state.closes.push({ code, reason }); },
    send(chunk) { state.sent.push(Array.from(chunk)); },
  };
  const socket = {
    opened, closed: closed.promise,
    writable: { getWriter: () => ({
      ready: Promise.resolve(),
      async write(chunk) { writes.push(Array.from(chunk)); if (write) await write(chunk); },
    }) },
    readable,
    async close() {
      state.socketCloses++;
      try { readController.close(); } catch { /* already closed or errored */ }
      closed.resolve();
    },
  };
  const context = vm.createContext({
    URL, Uint8Array, ArrayBuffer, setTimeout: timeout ? (fn) => setTimeout(fn, 0) : setTimeout, clearTimeout,
    Response: class {
      constructor(body, options) { this.body = body; Object.assign(this, options); }
    },
    WebSocketPair: class { constructor() { this[0] = {}; this[1] = server; } },
  });
  const sockets = new vm.SyntheticModule(["connect"], function () {
    this.setExport("connect", (address) => {
      state.connects++;
      state.address = address;
      return socket;
    });
  }, { context });
  const module = new vm.SourceTextModule(source, { context });
  await module.link((name) => {
    assert.equal(name, "cloudflare:sockets");
    return sockets;
  });
  await module.evaluate();
  return {
    ...state,
    state, writes, reads, closed, socket,
    download(chunk) { readController.enqueue(chunk); },
    eof() { readController.close(); },
    message(data) { events.get("message")({ data }); },
    event(name) { events.get(name)({}); },
    fetch(path = "/apiws?dst=149.154.167.51&dc=2", headers = {}, env = {}) {
      return module.namespace.default.fetch(new Request(`https://example.workers.dev${path}`, {
        headers: { Upgrade: "websocket", "Sec-WebSocket-Protocol": "binary", ...headers },
      }), env);
    },
  };
}

test("HTTP deployment check does not claim Telegram connectivity", async () => {
  const f = await fixture();
  assert.equal((await f.fetch("/apiws", { Upgrade: "" })).status, 426);
  assert.equal(f.state.connects, 0);
});

test("reject unauthorized destinations, token and subprotocol before opening TCP", async () => {
  const f = await fixture();
  assert.equal((await f.fetch("/wrong")).status, 404);
  assert.equal((await f.fetch("/apiws?dst=127.0.0.1")).status, 403);
  assert.equal((await f.fetch(undefined, {}, { TGLOCK_TOKEN: "test-token" })).status, 403);
  assert.equal((await f.fetch(undefined, { "Sec-WebSocket-Protocol": "chat" })).status, 400);
  assert.equal(f.state.connects, 0);
});

test("wait for upstream TCP before accepting WebSocket", async () => {
  const opened = deferred();
  const f = await fixture({ opened: opened.promise });
  const response = f.fetch();
  await tick();
  assert.equal(f.state.accepted, false);
  opened.resolve();
  const result = await response;
  assert.equal(result.status, 101);
  assert.equal(result.headers["Sec-WebSocket-Protocol"], "binary");
  assert.equal(f.state.accepted, true);
  f.event("close");
});

test("failed upstream returns HTTP 502, never a successful tunnel", async () => {
  const f = await fixture({ opened: Promise.reject(new Error("unreachable")) });
  assert.equal((await f.fetch()).status, 502);
  assert.equal(f.state.accepted, false);
  assert.equal(f.state.socketCloses, 1);
});

test("upstream timeout returns 504 and cancels socket", async () => {
  const f = await fixture({ opened: new Promise(() => {}), timeout: true });
  assert.equal((await f.fetch()).status, 504);
  assert.equal(f.state.accepted, false);
  assert.equal(f.state.socketCloses, 1);
});

test("serialize binary writes, preserve bytes and view offsets", async () => {
  const firstWrite = deferred();
  let calls = 0;
  const f = await fixture({ write: async () => { if (++calls === 1) await firstWrite.promise; } });
  await f.fetch();
  f.message(new Uint8Array([1, 2]).buffer);
  f.message(new Uint8Array([99, 3, 4, 88]).subarray(1, 3));
  await tick();
  assert.deepEqual(f.writes, [[1, 2]]);
  firstWrite.resolve();
  await tick();
  assert.deepEqual(f.writes, [[1, 2], [3, 4]]);
  f.event("close");
});

test("overflow closes socket and discards queued writes", async () => {
  const f = await fixture();
  await f.fetch();
  f.message(new Uint8Array(1024 * 1024).buffer);
  f.message(new Uint8Array([1]).buffer);
  await tick();
  assert.equal(f.state.closes[0].code, 1009);
  assert.equal(f.state.socketCloses, 1);
  assert.equal(f.writes.length, 0);
});

test("empty-message floods have a bounded queue too", async () => {
  const f = await fixture();
  await f.fetch();
  for (let i = 0; i < 257; i++) f.message(new ArrayBuffer(0));
  await tick();
  assert.equal(f.state.closes[0].code, 1009);
  assert.equal(f.state.socketCloses, 1);
});

test("text and write failures get diagnostic close codes", async () => {
  const f = await fixture();
  await f.fetch();
  f.message("not binary");
  assert.equal(f.state.closes[0].code, 1003);
  const failing = await fixture({ write: async () => { throw new Error("reset"); } });
  await failing.fetch();
  failing.message(new Uint8Array([1]).buffer);
  await tick();
  assert.equal(failing.state.closes[0].code, 1011);
  assert.equal(failing.state.socketCloses, 1);
});

test("read errors propagate and close both socket directions", async () => {
  const f = await fixture();
  await f.fetch();
  f.reads.reject(new Error("reset"));
  await tick();
  assert.equal(f.state.closes[0].code, 1011);
  assert.equal(f.state.socketCloses, 1);
});

test("Telegram bytes reach WebSocket unchanged and EOF closes both directions", async () => {
  const f = await fixture();
  await f.fetch();
  f.download(new Uint8Array([0, 255, 128]));
  f.download(new Uint8Array([1, 2]));
  f.eof();
  await tick();
  assert.deepEqual(f.state.sent, [[0, 255, 128], [1, 2]]);
  assert.equal(f.state.closes[0].code, 1000);
  assert.equal(f.state.socketCloses, 1);
});

test("CDN worker keeps the requested DC203 destination", async () => {
  const f = await fixture();
  await f.fetch("/apiws?dst=91.105.192.100&dc=203");
  assert.equal(f.state.address.hostname, "91.105.192.100");
  assert.equal(f.state.address.port, 443);
  f.event("close");
});
