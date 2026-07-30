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

export default {
  async fetch(request, env) {
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

    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    const upstream = connect({ hostname: destination, port: TELEGRAM_PORT });
    const writer = upstream.writable.getWriter();
    let closed = false;

    const shutdown = () => {
      if (closed) return;
      closed = true;
      writer.close().catch(() => {});
      try {
        server.close();
      } catch {
        // соединение уже закрыто
      }
    };

    server.addEventListener("message", (event) => {
      const chunk =
        event.data instanceof ArrayBuffer
          ? new Uint8Array(event.data)
          : event.data;
      writer.write(chunk).catch(shutdown);
    });
    server.addEventListener("close", shutdown);
    server.addEventListener("error", shutdown);

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
        // разрыв соединения — обычная ситуация, не ошибка
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
