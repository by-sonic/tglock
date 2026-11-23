import { once } from "node:events";
import { createServer } from "node:net";
import { spawn } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const [port, version, temp] = process.argv.slice(2);
const path = "ws://127.0.0.1:" + port + "/apiws?dc=203&dst=91.105.192.100";
const response = await fetch(path.replace("ws:", "http:"));
console.log("Plain GET", version, response.status, (await response.text()).trim());
if (response.status !== 426) throw Error("Expected upgrade-required status");

// The project probe fixes the naked Telegram CDN target. Substitute only the
// transport endpoint to exercise the same wire bytes through the real Worker.
let closeCode;
const bridge = createServer((client) => {
  client.pause();
  const upstream = new WebSocket(path, "binary");
  upstream.binaryType = "arraybuffer";
  upstream.onopen = () => {
    console.log("Worker WebSocket negotiated", upstream.protocol);
    client.on("data", (data) => upstream.send(data));
    client.resume();
  };
  upstream.onmessage = ({ data }) => client.write(Buffer.from(data));
  upstream.onclose = ({ code, reason }) => {
    closeCode = code;
    console.log("Worker close", code, reason);
    client.destroy();
  };
  upstream.onerror = () => { console.log("Worker transport error"); client.destroy(); };
  client.on("error", () => {});
  client.on("close", () => upstream.close());
});
bridge.listen(0, "127.0.0.1");
await once(bridge, "listening");
try {
  const source = await readFile("scripts/probe_proxy.mjs", "utf8");
  const original = '{ host: "91.105.192.100", port: 443 }';
  if (source.split(original).length !== 2) throw Error("Unexpected probe source");
  const fixture = join(temp, "worker-cdn-probe.mjs");
  await writeFile(fixture, source.replace(original, '{ host: "127.0.0.1", port: ' + bridge.address().port + " }"));
  const probe = spawn(process.execPath, [fixture, "--direct-cdn", "--dc", "203", "--timeout-ms", "16000"], { stdio: "inherit" });
  const [exit] = await once(probe, "exit");
  if (version === "15") {
    if (exit === 0 || closeCode !== 1003) throw Error("Expected the reported historical binary close 1003");
    console.log("Historical Worker beta.15 reproduced 1003");
  } else {
    if (exit !== 0) throw Error("Missing nonce-matched resPQ from Telegram CDN through Worker");
    console.log("Current released Worker passed end-to-end CDN exchange");
  }
} finally {
  bridge.close();
}
