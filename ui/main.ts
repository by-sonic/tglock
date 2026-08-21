import { invoke } from "@tauri-apps/api/core";
import "./styles.css";

type View = "home" | "settings" | "diagnostics";

type Status = {
  running: boolean;
  activeConnections: number;
  tunnels: number;
  dataCenter: number | null;
  route: string;
  failures: number;
  routeFailures: number;
  /// Отклонено политикой «в LAN-режиме только Telegram».
  blocked: number;
  /// Клиенты, которые дошли, но не сумели договориться о рукопожатии.
  unknownClients: number;
  uptimeSeconds: number;
  port: number;
  /// Адрес для других устройств. Приходит только в LAN-режиме.
  shareAddress: string | null;
  /// Полная ссылка tg://proxy для подключения Telegram.
  telegramLink: string | null;
  /// Секрет сохранён и не изменится после перезапуска.
  secretPersistent: boolean;
  /// Почему секрет не записался на диск.
  secretWriteError: string | null;
  logs: LogLine[];
};

type LogLine = {
  timestamp: string;
  message: string;
  error: boolean;
};

type Settings = {
  lanMode: boolean;
  port: number;
  workerDomain: string;
  secret?: string | null;
};

const root = document.querySelector<HTMLDivElement>("#app")!;

let view: View = "home";
let status: Status = {
  running: false,
  activeConnections: 0,
  tunnels: 0,
  dataCenter: null,
  route: "Маршрут ещё не выбран",
  failures: 0,
  routeFailures: 0,
  blocked: 0,
  unknownClients: 0,
  uptimeSeconds: 0,
  port: 1080,
  shareAddress: null,
  telegramLink: null,
  secretPersistent: true,
  secretWriteError: null,
  logs: [],
};
let settings: Settings = { lanMode: false, port: 1080, workerDomain: "" };
let busy = false;
let toastTimer: number | undefined;

const icons = {
  arrowLeft: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m15 18-6-6 6-6"/></svg>`,
  settings: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-2.86 2.86-.06-.06A1.7 1.7 0 0 0 15 19.4a1.7 1.7 0 0 0-1 .6 1.7 1.7 0 0 0-.4 1.1V21H9.6v-.1A1.7 1.7 0 0 0 8.5 19.4a1.7 1.7 0 0 0-1.88.34l-.06.06L3.7 16.94l.06-.06A1.7 1.7 0 0 0 4.1 15a1.7 1.7 0 0 0-.6-1 1.7 1.7 0 0 0-1.1-.4H2.3V9.6h.1A1.7 1.7 0 0 0 4.1 8.5a1.7 1.7 0 0 0-.34-1.88l-.06-.06L6.56 3.7l.06.06A1.7 1.7 0 0 0 8.5 4.1a1.7 1.7 0 0 0 1-.6 1.7 1.7 0 0 0 .4-1.1V2.3h4v.1A1.7 1.7 0 0 0 15 4.1a1.7 1.7 0 0 0 1.88-.34l.06-.06 2.86 2.86-.06.06A1.7 1.7 0 0 0 19.4 8.5a1.7 1.7 0 0 0 .6 1 1.7 1.7 0 0 0 1.1.4h.1v4h-.1a1.7 1.7 0 0 0-1.7 1.1Z"/></svg>`,
  activity: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 12h4l2.4-7 5.1 14 2.4-7H21"/></svg>`,
  plane: `<svg viewBox="0 0 64 64" aria-hidden="true"><path fill="currentColor" d="M52.4 11.7 8.2 28.8c-3 1.2-3 2.8-.6 3.5l11.3 3.5 4.4 13.4c.5 1.5.3 2.1 1.8 2.1 1.2 0 1.7-.5 2.4-1.2l5.5-5.3 11.5 8.5c2.1 1.2 3.7.6 4.2-2l7.6-35.8c.8-3.1-1.2-4.5-3.9-3.8ZM22.7 35l22.1-13.9c1.1-.7 2.1-.3 1.3.4L27.9 38l-.7 7.4L22.7 35Z"/></svg>`,
};

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function formatUptime(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  return [hours, minutes, rest].map((value) => value.toString().padStart(2, "0")).join(":");
}

function connectionState(): { title: string; subtitle: string; className: string } {
  if (!status.running) {
    return {
      title: "Защита выключена",
      subtitle: "Нажмите кнопку, чтобы подключить Telegram",
      className: "offline",
    };
  }
  if (status.failures > 0 && status.tunnels === 0) {
    return {
      title: "Ищем новый маршрут",
      subtitle: "Переключаемся на резервное подключение",
      className: "warning",
    };
  }
  if (status.tunnels > 0) {
    return {
      title: "Telegram на связи",
      subtitle: "Соединение защищено и работает",
      className: "online",
    };
  }
  return {
    title: "Защита включена",
    subtitle: "Откройте Telegram — маршрут готов",
    className: "online",
  };
}

function shell(content: string, pageClass = ""): string {
  return `
    <main class="app-shell ${pageClass}">
      <div class="drag-region" data-tauri-drag-region></div>
      ${content}
      <div id="toast" class="toast" role="status"></div>
    </main>
  `;
}

function renderHome(): void {
  const connection = connectionState();
  root.innerHTML = shell(`
    <section class="home">
      <header class="brand">
        <div class="wordmark"><span>TG</span>Lock</div>
        <p>Свободный Telegram. В один клик.</p>
      </header>

      <div class="hero ${connection.className}">
        <div class="orb-field">
          <div class="orbit orbit-one"></div>
          <div class="orbit orbit-two"></div>
          <div class="orb">
            <div class="orb-shine"></div>
            ${icons.plane}
          </div>
        </div>
        <div class="connection-copy">
          <div class="status-line">
            <span class="status-dot"></span>
            <h1>${connection.title}</h1>
          </div>
          <p>${connection.subtitle}</p>
        </div>
      </div>

      <button id="power" class="power-button ${status.running ? "stop" : ""}" ${busy ? "disabled" : ""}>
        <span>${busy ? "Подождите…" : status.running ? "Выключить" : "Включить защиту"}</span>
        <span class="button-arrow">→</span>
      </button>

      <div class="route-pill">
        <span class="route-pulse"></span>
        <span>${escapeHtml(status.route)}</span>
        <span class="route-separator">·</span>
        <span>порт ${status.port}</span>
      </div>

      ${status.secretWriteError || !status.secretPersistent ? `
      <div class="notice-card warning">
        <strong>Секрет не сохранён</strong>
        <p>${status.secretWriteError
          ? escapeHtml(status.secretWriteError)
          : "После перезапуска ссылка tg://proxy изменится, и Telegram откажет старой."}</p>
        <p class="field-hint">Закрепите секрет в настройках или проверьте права на папку приложения.</p>
      </div>` : ""}

      ${status.telegramLink ? `
      <div class="share-card">
        <div class="share-label">Ссылка для Telegram</div>
        <button id="copy-link" class="share-address" title="Нажмите, чтобы скопировать">
          ${escapeHtml(status.telegramLink)}
        </button>
        <div class="share-hint">
          Откройте её в Telegram на этом или другом устройстве. Если прокси «настроен неверно» —
          скопируйте ссылку заново: секрет мог измениться после прошлого запуска.
        </div>
      </div>` : ""}

      ${status.shareAddress ? `
      <div class="share-card">
        <div class="share-label">Адрес для других устройств</div>
        <button id="copy-address" class="share-address" title="Нажмите, чтобы скопировать">
          ${escapeHtml(status.shareAddress)}
        </button>
        <div class="share-hint">
          Впишите его в Telegram на телефоне. Не <code>127.0.0.1</code> — на другом
          устройстве это означает само устройство.
        </div>
      </div>` : ""}

      <nav class="bottom-nav" aria-label="Разделы">
        <button id="settings-nav" class="nav-button">
          <span class="nav-icon">${icons.settings}</span>
          <span>Настройки</span>
        </button>
        <div class="nav-divider"></div>
        <button id="diagnostics-nav" class="nav-button">
          <span class="nav-icon">${icons.activity}</span>
          <span>Диагностика</span>
        </button>
      </nav>
    </section>
  `, "home-page");

  document.querySelector("#power")?.addEventListener("click", toggleProtection);
  document.querySelector("#copy-link")?.addEventListener("click", copyTelegramLink);
  document.querySelector("#copy-address")?.addEventListener("click", copyShareAddress);
  document.querySelector("#settings-nav")?.addEventListener("click", () => navigate("settings"));
  document.querySelector("#diagnostics-nav")?.addEventListener("click", () => navigate("diagnostics"));
}

function pageHeader(title: string, subtitle: string): string {
  return `
    <header class="page-header">
      <button class="back-button" id="back" aria-label="Назад">${icons.arrowLeft}</button>
      <div>
        <h1>${title}</h1>
        <p>${subtitle}</p>
      </div>
    </header>
  `;
}

function renderSettings(): void {
  root.innerHTML = shell(`
    <section class="subpage">
      ${pageHeader("Настройки", "Подключение и локальная сеть")}

      <form id="settings-form" class="settings-form">
        <div class="setting-card">
          <label class="field-label" for="worker">Cloudflare Worker</label>
          <input
            id="worker"
            name="worker"
            type="text"
            value="${escapeHtml(settings.workerDomain)}"
            placeholder="example.workers.dev"
            autocomplete="off"
            ${status.running ? "disabled" : ""}
          />
          <p class="field-hint">Необязательно. Используется как резервный маршрут.</p>
        </div>

        <div class="setting-card">
          <label class="field-label" for="secret">Секрет прокси</label>
          <input
            id="secret"
            name="secret"
            type="text"
            value="${escapeHtml(settings.secret ?? "")}"
            placeholder="dd… или 32 hex (необязательно)"
            autocomplete="off"
            spellcheck="false"
            ${status.running ? "disabled" : ""}
          />
          <p class="field-hint">
            Пусто — секрет хранится в файле рядом с настройками. Закрепите вручную, если Telegram
            отвергает прокси после перезапуска.
          </p>
        </div>

        <div class="setting-list">
          <label class="setting-row" for="lan-mode">
            <span>
              <strong>Доступ из локальной сети</strong>
              <small>Подключение других устройств</small>
            </span>
            <span class="switch">
              <input id="lan-mode" type="checkbox" ${settings.lanMode ? "checked" : ""} ${status.running ? "disabled" : ""}/>
              <span class="switch-track"></span>
            </span>
          </label>
          <div class="setting-rule"></div>
          <label class="setting-row compact" for="port">
            <span>
              <strong>Локальный порт</strong>
              <small>SOCKS5 и MTProto</small>
            </span>
            <input id="port" class="port-input" type="number" min="1" max="65535" value="${settings.port}" ${status.running ? "disabled" : ""}/>
          </label>
        </div>

        ${status.running ? `<div class="locked-note"><span></span>Выключите защиту, чтобы изменить настройки</div>` : ""}

        <button class="save-button" type="submit" ${status.running || busy ? "disabled" : ""}>
          ${busy ? "Сохраняю…" : "Сохранить настройки"}
        </button>
      </form>
    </section>
  `, "subpage-shell");

  document.querySelector("#back")?.addEventListener("click", () => navigate("home"));
  document.querySelector("#settings-form")?.addEventListener("submit", saveSettings);
}

function renderDiagnostics(): void {
  const recentLogs = status.logs.slice(-4).reverse();
  root.innerHTML = shell(`
    <section class="subpage">
      ${pageHeader("Диагностика", "Состояние маршрута в реальном времени")}

      <div class="connection-banner ${status.running ? "active" : ""}">
        <span class="banner-icon">${icons.activity}</span>
        <div>
          <strong>${status.running ? "Сервис работает" : "Сервис остановлен"}</strong>
          <small>${status.running ? "Локальный прокси принимает подключения" : "Включите защиту на главном экране"}</small>
        </div>
      </div>

      <div class="metrics-grid">
        <article class="metric-card">
          <span>Соединения</span>
          <strong>${status.activeConnections}</strong>
        </article>
        <article class="metric-card">
          <span>Туннели</span>
          <strong>${status.tunnels}</strong>
        </article>
        <article class="metric-card">
          <span>Дата-центр</span>
          <strong>${status.dataCenter ? `DC${status.dataCenter}` : "—"}</strong>
        </article>
        <article class="metric-card">
          <span>Время работы</span>
          <strong class="time">${formatUptime(status.uptimeSeconds)}</strong>
        </article>
        <article class="metric-card">
          <span>Падений маршрутов</span>
          <strong>${status.routeFailures}</strong>
        </article>
        <article class="metric-card">
          <span>Отклонено</span>
          <strong>${status.blocked}</strong>
        </article>
        <article class="metric-card">
          <span>Не опознаны</span>
          <strong>${status.unknownClients}</strong>
        </article>
      </div>

      <p class="field-hint">
        «Падений маршрутов» больше нуля при работающем Telegram — это норма:
        значит закреплённый адрес недоступен и подключение идёт через запасной.
        Число в багрепорте помогает понять, что именно перебиралось.
      </p>

      <p class="field-hint">
        «Отклонено» — запросы, которые LAN-режим не пропустил: он ходит только
        по адресам Telegram. Если с телефона ничего не работает, а здесь ноль и
        соединений тоже ноль, значит телефон до этого компьютера не дошёл —
        дело в сети или брандмауэре. Какие именно адреса отклонены, видно ниже.
      </p>

      <p class="field-hint">
        «Не опознаны» — клиенты, которые дошли до прокси, но договориться с ними
        не удалось. Почти всегда это старая ссылка: секрет в Telegram остался от
        прошлого запуска и больше не совпадает. Тогда Telegram пишет «прокси
        настроен неверно», а адрес такого клиента появится в журнале ниже.
      </p>

      <div class="log-panel">
        <div class="log-heading">
          <span>Последние события</span>
          <span class="live-label"><i></i>LIVE</span>
        </div>
        <div class="logs">
          ${recentLogs.length
            ? recentLogs
                .map(
                  (line) => `
                    <div class="log-line ${line.error ? "error" : ""}">
                      <time>${line.timestamp}</time>
                      <span>${escapeHtml(line.message)}</span>
                    </div>`,
                )
                .join("")
            : `<div class="empty-log">События появятся после включения защиты</div>`}
        </div>
      </div>
    </section>
  `, "subpage-shell");

  document.querySelector("#back")?.addEventListener("click", () => navigate("home"));
}

function render(): void {
  if (view === "settings") renderSettings();
  else if (view === "diagnostics") renderDiagnostics();
  else renderHome();
}

function navigate(next: View): void {
  view = next;
  render();
}

async function refreshStatus(): Promise<void> {
  try {
    status = await invoke<Status>("get_status");
    if (view !== "settings") render();
  } catch (error) {
    showToast(String(error), true);
  }
}

async function toggleProtection(): Promise<void> {
  if (busy) return;
  busy = true;
  renderHome();
  try {
    status = status.running
      ? await invoke<Status>("stop_proxy")
      : await invoke<Status>("start_proxy");
  } catch (error) {
    showToast(String(error), true);
  } finally {
    busy = false;
    await refreshStatus();
  }
}

async function saveSettings(event: Event): Promise<void> {
  event.preventDefault();
  if (busy || status.running) return;
  const worker = document.querySelector<HTMLInputElement>("#worker");
  const secret = document.querySelector<HTMLInputElement>("#secret");
  const lanMode = document.querySelector<HTMLInputElement>("#lan-mode");
  const port = document.querySelector<HTMLInputElement>("#port");
  if (!worker || !secret || !lanMode || !port) return;

  const parsedPort = Number(port.value);
  if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
    showToast("Порт должен быть от 1 до 65535", true);
    return;
  }

  busy = true;
  settings = {
    workerDomain: worker.value.trim(),
    lanMode: lanMode.checked,
    port: parsedPort,
    secret: secret.value.trim() || null,
  };
  renderSettings();
  try {
    settings = await invoke<Settings>("save_settings", { settings });
    showToast("Настройки сохранены");
    window.setTimeout(() => navigate("home"), 350);
  } catch (error) {
    showToast(String(error), true);
  } finally {
    busy = false;
  }
}

async function copyTelegramLink(): Promise<void> {
  const link = status.telegramLink;
  if (!link) return;
  try {
    await navigator.clipboard.writeText(link);
    showToast("Ссылка скопирована");
  } catch {
    showToast("Скопируйте ссылку вручную", true);
  }
}

async function copyShareAddress(): Promise<void> {
  const address = status.shareAddress;
  if (!address) return;
  try {
    await navigator.clipboard.writeText(address);
    showToast("Адрес скопирован");
  } catch {
    // Буфер обмена может быть недоступен — адрес и так виден на экране.
    showToast("Скопируйте адрес вручную", true);
  }
}

function showToast(message: string, error = false): void {
  window.clearTimeout(toastTimer);
  window.requestAnimationFrame(() => {
    const toast = document.querySelector<HTMLDivElement>("#toast");
    if (!toast) return;
    toast.textContent = message.replace(/^["']|["']$/g, "");
    toast.className = `toast visible${error ? " error" : ""}`;
    toastTimer = window.setTimeout(() => toast.classList.remove("visible"), 2800);
  });
}

async function bootstrap(): Promise<void> {
  try {
    [status, settings] = await Promise.all([
      invoke<Status>("get_status"),
      invoke<Settings>("get_settings"),
    ]);
  } catch {
    // The browser preview intentionally uses the initial local state.
  }
  render();
  window.setInterval(refreshStatus, 1000);
}

void bootstrap();
