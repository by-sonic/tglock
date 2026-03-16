<p align="center">
  <h1 align="center">TG Unblock</h1>
  <p align="center">
    <b>Обход блокировки Telegram через WebSocket-туннель</b><br>
    Без VPN. Без серверов. Без абонентки. Один клик.
  </p>
  <p align="center">
    <a href="https://github.com/by-sonic/tglock/releases"><img src="https://img.shields.io/github/v/release/by-sonic/tglock?style=for-the-badge&color=blue" alt="Release"></a>
    <a href="https://github.com/by-sonic/tglock/blob/main/LICENSE"><img src="https://img.shields.io/github/license/by-sonic/tglock?style=for-the-badge" alt="License"></a>
    <a href="https://github.com/by-sonic/tglock/stargazers"><img src="https://img.shields.io/github/stars/by-sonic/tglock?style=for-the-badge&color=yellow" alt="Stars"></a>
    <img src="https://img.shields.io/badge/rust-1.70%2B-orange?style=for-the-badge&logo=rust" alt="Rust">
    <img src="https://img.shields.io/badge/platform-Windows-0078D6?style=for-the-badge&logo=windows" alt="Windows">
  </p>
</p>

---

## Что это?

**TG Unblock** — десктопное приложение на Rust, которое обходит блокировку Telegram через локальный WebSocket-прокси. Провайдер видит обычный HTTPS к `web.telegram.org`, а не MTProto — DPI не может обнаружить и заблокировать трафик.

### Почему не GoodbyeDPI / Zapret?

| | GoodbyeDPI | Zapret | **TG Unblock** |
|---|---|---|---|
| Метод | Фрагментация пакетов | Desync пакетов | WebSocket-туннель |
| DPI видит MTProto? | Нет (обфускация) | Нет (desync) | **Нет (обычный HTTPS)** |
| IP-шейпинг обходит? | Нет | Нет | **Да** |
| Скорость | Зависит от DPI | Зависит от DPI | **Полная** |
| Переподключения | Возможны | Возможны | **Нет** |
| Настройка | Много параметров | Стратегии | **Один клик** |

## Скачать

> **[Скачать последний релиз](https://github.com/by-sonic/tglock/releases)**

Или собрать из исходников:

```bash
git clone https://github.com/by-sonic/tglock.git
cd tglock
cargo build --release
```

Готовый `.exe` будет в `target/release/tg_unblock.exe`.

## Как пользоваться

1. Запустите `tg_unblock.exe`
2. Нажмите **"Запустить обход"**
3. Нажмите **"Настроить автоматически"** — откроется Telegram, нажмите "Подключить"
4. Готово. Telegram работает на полной скорости.

### Ручная настройка прокси

Если автонастройка не сработала:

**Telegram Desktop** → Настройки → Продвинутые → Тип соединения → **Использовать SOCKS5-прокси**

| Параметр | Значение |
|---|---|
| Сервер | `127.0.0.1` |
| Порт | `1080` |
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
| DC1 | `149.154.160.0/22` | `wss://pluto.web.telegram.org/apiws` |
| DC2 | `149.154.164.0/22` | `wss://venus.web.telegram.org/apiws` |
| DC3 | `149.154.168.0/22` | `wss://aurora.web.telegram.org/apiws` |
| DC4 | `91.108.12.0/22` | `wss://vesta.web.telegram.org/apiws` |
| DC5 | `91.108.56.0/22` | `wss://flora.web.telegram.org/apiws` |

Имена DC (`pluto`, `venus`, `aurora`, `vesta`, `flora`) — из [официальной документации MTProto](https://core.telegram.org/mtproto/transports).

## Стек

| Что | Зачем |
|---|---|
| **Rust** | Скорость, безопасность, один бинарник без зависимостей |
| **egui / eframe** | Нативный GUI без Electron, без браузера |
| **tokio** | Async I/O для высокопроизводительного проксирования |
| **tokio-tungstenite** | WebSocket-клиент с TLS |
| **native-tls** | TLS через системные сертификаты Windows |

## Структура проекта

```
tglock/
├── Cargo.toml          # Зависимости
├── src/
│   ├── main.rs         # GUI + управление прокси
│   ├── ws_proxy.rs     # SOCKS5-сервер + WebSocket-туннель
│   ├── bypass.rs       # DNS-настройка, утилиты Windows
│   └── network.rs      # Сетевая диагностика
└── tg_blacklist.txt    # IP-подсети и домены Telegram
```

## Требования

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
