<p align="center">
  <h1 align="center">TG Unblock</h1>
  <p align="center">
    <b>Обход блокировки Telegram через WebSocket-туннель</b><br>
    Без VPN. Без серверов. Без абонентки. CLI + GUI.
  </p>
  <p align="center">
    <a href="https://github.com/by-sonic/tglock/releases"><img src="https://img.shields.io/github/v/release/by-sonic/tglock?style=for-the-badge&color=blue" alt="Release"></a>
    <a href="https://github.com/by-sonic/tglock/blob/main/LICENSE"><img src="https://img.shields.io/github/license/by-sonic/tglock?style=for-the-badge" alt="License"></a>
    <a href="https://github.com/by-sonic/tglock/stargazers"><img src="https://img.shields.io/github/stars/by-sonic/tglock?style=for-the-badge&color=yellow" alt="Stars"></a>
    <img src="https://img.shields.io/badge/rust-1.70%2B-orange?style=for-the-badge&logo=rust" alt="Rust">
    <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-0078D6?style=for-the-badge" alt="Platform">
  </p>
</p>

---

## Что это?

**TG Unblock** — кроссплатформенное приложение на Rust, которое обходит блокировку Telegram через локальный WebSocket-прокси. Провайдер видит обычный HTTPS к `web.telegram.org`, а не MTProto — DPI не может обнаружить и заблокировать трафик.

Доступно в двух вариантах:
- **CLI** — кроссплатформенный (Linux, macOS, Windows), работает в терминале
- **GUI** — графический интерфейс для Windows

### Почему не GoodbyeDPI / Zapret?

| | GoodbyeDPI | Zapret | **TG Unblock** |
|---|---|---|---|
| Метод | Фрагментация пакетов | Desync пакетов | WebSocket-туннель |
| DPI видит MTProto? | Нет (обфускация) | Нет (desync) | **Нет (обычный HTTPS)** |
| IP-шейпинг обходит? | Нет | Нет | **Да** |
| Скорость | Зависит от DPI | Зависит от DPI | **Полная** |
| Переподключения | Возможны | Возможны | **Нет** |
| Настройка | Много параметров | Стратегии | **Один клик / одна команда** |

## Скачать

> **[Скачать последний релиз](https://github.com/by-sonic/tglock/releases)**

Или собрать из исходников:

```bash
git clone https://github.com/by-sonic/tglock.git
cd tglock

# CLI (Linux / macOS / Windows):
cargo build --release --bin tg_unblock

# GUI (Windows):
cargo build --release --bin tg_unblock_gui --features gui
```

Готовый бинарник будет в `target/release/`.

## Как пользоваться

### CLI (Linux / macOS / Windows)

```bash
# Запустить прокси на порту по умолчанию (1080):
tg_unblock

# Указать порт:
tg_unblock --port 9050

# Со сменой DNS на Cloudflare (нужен root/admin):
sudo tg_unblock --dns
```

Остановка — `Ctrl+C` (DNS автоматически сбросится).

```
$ tg_unblock --help
Обход блокировки Telegram через WebSocket-туннель

Usage: tg_unblock [OPTIONS]

Options:
  -p, --port <PORT>  Порт SOCKS5-прокси [default: 1080]
  -b, --bind <BIND>  Адрес привязки [default: 127.0.0.1]
      --dns          Сменить DNS на Cloudflare 1.1.1.1 (нужен root/admin)
  -h, --help         Print help
  -V, --version      Print version
```

### GUI (Windows)

1. Запустите `tg_unblock_gui.exe`
2. Нажмите **"Запустить обход"**
3. Нажмите **"Настроить автоматически"** — откроется Telegram, нажмите "Подключить"
4. Готово. Telegram работает на полной скорости.

### Настройка прокси в Telegram

**Telegram Desktop** → Настройки → Продвинутые → Тип соединения → **Использовать SOCKS5-прокси**

| Параметр | Значение |
|---|---|
| Сервер | `127.0.0.1` |
| Порт | `1080` (или тот, что указали в `--port`) |
| Логин | *пусто* |
| Пароль | *пусто* |

## Как это работает

```
Telegram Desktop
       │
       ▼ (SOCKS5)
┌──────────────────┐
│  TG Unblock      │  127.0.0.1:1080
│  WS-прокси       │
└──────┬───────────┘
       │
       ▼ (определяет DC по IP)
       │
       ├── Telegram IP? ──► WSS-туннель к {dc}.web.telegram.org/apiws
       │                    (провайдер видит обычный HTTPS)
       │
       └── Другой IP? ────► Прямое TCP-соединение (без изменений)
```

### DC-маппинг

Приложение автоматически определяет Data Center по IP-адресу и маршрутизирует через правильный WebSocket-эндпоинт:

| DC | Подсеть | WebSocket |
|---|---|---|
| DC1 | `149.154.160.0/22` | `wss://kws1.web.telegram.org/apiws` |
| DC2 | `149.154.164.0/22` | `wss://kws2.web.telegram.org/apiws` |
| DC3 | `149.154.168.0/22` | `wss://kws3.web.telegram.org/apiws` |
| DC4 | `91.108.12.0/22` | `wss://kws4.web.telegram.org/apiws` |
| DC5 | `91.108.56.0/22` | `wss://kws5.web.telegram.org/apiws` |

## Стек

| Что | Зачем |
|---|---|
| **Rust** | Скорость, безопасность, один бинарник без зависимостей |
| **tokio** | Async I/O для высокопроизводительного проксирования |
| **tokio-tungstenite** | WebSocket-клиент с TLS |
| **native-tls** | TLS через системные сертификаты |
| **clap** | Парсинг аргументов CLI |
| **egui / eframe** | Нативный GUI (опционально, Windows) |

## Структура проекта

```
tglock/
├── Cargo.toml              # Зависимости и таргеты
├── src/
│   ├── lib.rs              # Библиотечный крейт
│   ├── ws_proxy.rs         # SOCKS5-сервер + WebSocket-туннель
│   ├── bypass.rs           # DNS-настройка (Linux + Windows)
│   ├── network.rs          # Сетевая диагностика (Linux + Windows)
│   └── bin/
│       ├── cli.rs          # CLI-интерфейс (кроссплатформенный)
│       └── gui.rs          # GUI-интерфейс (Windows)
└── tg_blacklist.txt        # IP-подсети и домены Telegram
```

## Требования

### CLI (Linux / macOS)
- [Rust 1.70+](https://rustup.rs/) (для сборки из исходников)
- Права root (для смены DNS с флагом `--dns`, опционально)

### GUI (Windows)
- Windows 10/11
- [Rust 1.70+](https://rustup.rs/) (для сборки из исходников)
- Права администратора (для смены DNS, опционально)

## FAQ

**Q: Это VPN?**
A: Нет. Трафик не идёт через сторонние серверы. Прокси работает локально и туннелирует только Telegram-трафик через WebSocket к официальным серверам Telegram.

**Q: Это безопасно?**
A: Весь код открыт. Никакой телеметрии. Никаких данных не отправляется. Соединение с Telegram остаётся end-to-end зашифрованным (MTProto).

**Q: Будет ли работать с мобильным Telegram?**
A: Пока только Telegram Desktop. Для мобильных устройств рекомендуем [by sonic VPN](https://t.me/bysonicvpn_bot).

**Q: Замедляется ли интернет?**
A: Нет. Проксируется только трафик к серверам Telegram. Весь остальной трафик идёт напрямую.

**Q: Работает ли на Linux?**
A: Да. CLI-версия полностью кроссплатформенная. На Linux для смены DNS используется `resolvectl` (systemd-resolved) или прямая запись в `/etc/resolv.conf`.

## VPN для полного обхода

Если нужен обход блокировок для **всех** приложений (YouTube, Discord, Instagram и др.) — попробуйте **[by sonic VPN](https://t.me/bysonicvpn_bot)**. Быстрый, без ограничений скорости.

## Лицензия

MIT — делайте что хотите.

## Автор

**by sonic** — [@bysonicvpn_bot](https://t.me/bysonicvpn_bot)

---

<p align="center">
  <b>Если пригодилось — поставьте ⭐ на GitHub</b>
</p>
