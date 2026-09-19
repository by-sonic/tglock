// Резервный маршрут TGLock через Cloudflare Worker.
//
// Нужен в одном случае: провайдер заблокировал саму веб-инфраструктуру
// Telegram, и все обычные маршруты TGLock перестали отвечать. Тогда соединение
// идёт на твой домен *.workers.dev, а воркер доводит его до Telegram.
//
// Инструкция по установке: docs/CLOUDFLARE_WORKER.md
//
// Контракт, который ожидает клиент (src/transport.rs):
//   wss://<домен>/apiws?dst=<telegram-ip>&dc=<номер-dc>
//   заголовок Sec-WebSocket-Protocol: binary — его обязательно нужно
//   подтвердить в ответе, иначе клиент разорвёт рукопожатие;
//   бинарные frames в обе стороны, без обёрток.

import { connect } from "cloudflare:sockets";

// Только те адреса, которые запрашивает сам TGLock. Без этого списка любой,
// кто узнает адрес воркера, получит через твой аккаунт произвольный
// TCP-прокси.
const ALLOWED_DESTINATIONS = new Set([
  "91.105.192.100",
  "149.154.167.51",
  "149.154.167.91",
  "149.154.167.220",
  "149.154.171.5",
  "149.154.175.50",
  "149.154.175.100",
]);

const TELEGRAM_PORT = 443;
const CONNECT_TIMEOUT_MS = 3000;
// WebSocket events cannot be paused. Bound the outstanding writes instead of
// retaining an unlimited chain of promises when Telegram stops reading.
const MAX_PENDING_BYTES = 1024 * 1024;
const MAX_PENDING_MESSAGES = 256;

export default {
  async fetch(request, env = {}) {
    const url = new URL(request.url);

    if (url.pathname !== "/apiws") {
      return new Response("not found", { status: 404 });
    }
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("expected a websocket upgrade", { status: 426 });
    }
    // Необязательный общий секрет: задай переменную TGLOCK_TOKEN в настройках
    // воркера, и посторонние подключиться не смогут.
    if (env.TGLOCK_TOKEN && url.searchParams.get("token") !== env.TGLOCK_TOKEN) {
      return new Response("forbidden", { status: 403 });
    }

    const destination = url.searchParams.get("dst");
    if (!destination || !ALLOWED_DESTINATIONS.has(destination)) {
      return new Response("destination not allowed", { status: 403 });
    }

    if (!request.headers.get("Sec-WebSocket-Protocol")?.split(",").some((p) => p.trim() === "binary")) {
      return new Response("binary websocket subprotocol required", { status: 400 });
    }

    let upstream;
    let timer;
    let timedOut = false;
    try {
      upstream = connect({ hostname: destination, port: TELEGRAM_PORT });
      // Both promises can reject on connect failure; observe closed immediately.
      upstream.closed.catch(() => {});
      await Promise.race([
        upstream.opened,
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            timedOut = true;
            reject(new Error("connect timeout"));
          }, CONNECT_TIMEOUT_MS);
        }),
      ]);
    } catch {
      if (upstream) await upstream.close().catch(() => {});
      return new Response(timedOut ? "Telegram TCP connect timeout" : "Telegram TCP connect failed", {
        status: timedOut ? 504 : 502,
      });
    } finally {
      clearTimeout(timer);
    }

    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    const writer = upstream.writable.getWriter();
    let closed = false;

    const shutdown = (code = 1000, reason = "") => {
      if (closed) return;
      closed = true;
      // close() cancels both directions, including a blocked write/read.
      upstream.close().catch(() => {});
      try {
        server.close(code, reason);
      } catch {
        // соединение уже закрыто
      }
    };

    // Запись сериализуется: следующий чанк уходит только после того, как
    // записан предыдущий, и только когда писатель к этому готов.
    //
    // Раньше `write()` вызывался поверх незавершённого, а `writer.ready` не
    // спрашивался вовсе — backpressure не применялся. Пока в клиенте отправка
    // голодала, поверх воркера настоящего потока вверх не бывало и это не
    // проявлялось. Как только голодание починили, в воркер пошёл настоящий
    // поток (by-sonic/tglock#42).
    let pending = Promise.resolve();
    let pendingBytes = 0;
    let pendingMessages = 0;

    server.addEventListener("message", (event) => {
      if (closed) return;
      if (!(event.data instanceof ArrayBuffer) && !ArrayBuffer.isView(event.data)) {
        shutdown(1003, "binary messages required");
        return;
      }
      const chunk = event.data instanceof ArrayBuffer
        ? new Uint8Array(event.data)
        : new Uint8Array(event.data.buffer, event.data.byteOffset, event.data.byteLength);
      if (pendingBytes + chunk.byteLength > MAX_PENDING_BYTES || pendingMessages >= MAX_PENDING_MESSAGES) {
        shutdown(1009, "Telegram write queue full");
        return;
      }
      pendingBytes += chunk.byteLength;
      pendingMessages += 1;
      pending = pending
        .then(async () => {
          if (closed) return;
          await writer.ready;
          if (!closed) await writer.write(chunk);
        })
        .catch(() => shutdown(1011, "Telegram write failed"))
        .finally(() => {
          pendingBytes -= chunk.byteLength;
          pendingMessages -= 1;
        });
    });
    server.addEventListener("close", () => shutdown());
    server.addEventListener("error", () => shutdown(1011, "WebSocket failed"));
    upstream.closed.catch(() => shutdown(1011, "Telegram socket failed"));

    // Обратное направление: всё, что приходит от Telegram, уходит клиенту.
    (async () => {
      const reader = upstream.readable.getReader();
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          server.send(value);
        }
      } catch {
        shutdown(1011, "Telegram read failed");
      } finally {
        reader.releaseLock();
      }
      shutdown();
    })();

    return new Response(null, {
      status: 101,
      webSocket: client,
      // Обязательно: клиент запрашивает подпротокол binary и без
      // подтверждения рвёт рукопожатие.
      headers: { "Sec-WebSocket-Protocol": "binary" },
    });
  },
};
