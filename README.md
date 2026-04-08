<p align="center">
  <h1 align="center">TGLock</h1>
  <p align="center"><b>Обход блокировки Telegram через WebSocket-туннель</b></p>
  <p align="center">Без VPN. Без серверов. Без абонентки. Один клик.</p>
  <p align="center">
    <a href="https://github.com/by-sonic/tglock/releases/latest"><img src="https://img.shields.io/github/v/release/by-sonic/tglock?style=flat-square&color=blue" alt="Release"></a>
    <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-333?style=flat-square" alt="Platform">
    <img src="https://img.shields.io/badge/rust-stable-orange?style=flat-square&logo=rust" alt="Rust">
    <a href="LICENSE"><img src="https://img.shields.io/github/license/by-sonic/tglock?style=flat-square" alt="MIT"></a>
  </p>
</p>

---

## Скачать

**[Последний релиз](https://github.com/by-sonic/tglock/releases/latest)**

| Файл | Платформа |
|---|---|
| `tglock.exe` | Windows x64 |
| `tglock-macos-arm64` | macOS Apple Silicon (M1–M4) |
| `tglock-macos-x64` | macOS Intel |
| `tglock-linux-x64` | Linux x64 |

## Как пользоваться

1. Скачай и запусти
2. Нажми **ПОДКЛЮЧИТЬ**
3. Нажми **Настроить автоматически** → в Telegram нажми «Подключить»
4. Готово

Ручная настройка: Telegram → Настройки → Продвинутые → Тип соединения → SOCKS5 → `127.0.0.1:1080`

## Как это работает

```
Telegram Desktop → SOCKS5 (127.0.0.1:1080) → TGLock → WSS (web.telegram.org) → DC
```

1. Локальный SOCKS5-прокси перехватывает соединения Telegram
2. Из MTProto init-пакета извлекается номер DC (AES-256-CTR)
3. Трафик заворачивается в WebSocket через `kws{dc}.web.telegram.org`
4. Провайдер видит обычный HTTPS к `web.telegram.org`
5. Остальной трафик проходит напрямую

## Почему не GoodbyeDPI / Zapret?

GoodbyeDPI и Zapret фрагментируют пакеты чтобы обмануть DPI. Но если провайдер **шейпит по IP** — они бесполезны.

TGLock маскирует трафик под обычный HTTPS. DPI не видит MTProto. IP-шейпинг не работает — `web.telegram.org` не блокируется.

## Стек

| | |
|---|---|
| Rust | Один бинарник, нативная скорость |
| egui | GUI без браузера и Electron |
| tokio | Async I/O |
| tokio-tungstenite | WebSocket + TLS |

## Сборка

```bash
git clone https://github.com/by-sonic/tglock.git
cd tglock
cargo build --release
```

## VPN

Для обхода блокировок **всех** приложений — **[by sonic VPN](https://t.me/bysonicvpn_bot)**

## Лицензия

MIT

---

<p align="center"><b>by sonic</b></p>
