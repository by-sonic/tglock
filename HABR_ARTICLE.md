# Как я написал обход блокировки Telegram на Rust — без VPN, без серверов, через WebSocket

**Простой · 7 мин · Rust · Open source · Windows · Сетевые технологии · Из песочницы**

**TL;DR:** Написал open-source десктопное приложение **TG Unblock** на Rust, которое в один клик обходит блокировку Telegram через локальный WebSocket-прокси. Трафик заворачивается в обычный HTTPS к `web.telegram.org` — DPI не видит MTProto, провайдер не может шейпить. Без VPN, без серверов, без абонентки. Код на GitHub — [by-sonic/tglock](https://github.com/by-sonic/tglock).

---

## Предыстория: почему GoodbyeDPI не спасает

С весны 2025 года Telegram в России стал работать, мягко говоря, через боль. Сообщения доходят по 10 секунд, медиа не грузятся, звонки рвутся. Классическая картина: провайдер + DPI = страдания.

Первое, что приходит в голову — **GoodbyeDPI**. Запустил, пакеты фрагментируются, DPI не узнаёт MTProto... и вроде работает. Но:

- **Пинг 200+ мс** — при норме 40–60
- **Постоянные переподключения** — DPI переобучается и режет соединения
- **IP-шейпинг** — провайдер троттлит весь трафик к подсетям Telegram (149.154.x.x, 91.108.x.x)

GoodbyeDPI обманывает DPI на уровне пакетов, но **не решает проблему IP-шейпинга**. Если провайдер тупо режет скорость ко всем IP Telegram — хоть как фрагментируй, будет медленно.

VPN — вариант. Но:
- Платные стоят денег и сливают скорость
- Бесплатные сливают данные
- Не все работают стабильно
- Для одного Telegram гонять весь трафик через VPN — оверкилл

Нужно решение, которое **маскирует сам факт подключения к Telegram**, а не просто прячет протокол.

## Идея: WebSocket-туннель через web.telegram.org

Я провёл серию тестов. Прямое подключение к серверам Telegram (149.154.167.51:443) — либо таймаут, либо 200+ мс. А вот `web.telegram.org` отвечает стабильно за 50–80 мс через HTTPS. Провайдер его не трогает — это же «обычный сайт».

И тут я полез в [документацию MTProto](https://core.telegram.org/mtproto/transports) и нашёл золотую жилу:

> **WebSocket:** Implementation of the WebSocket transport is pretty much the same as with TCP... all data received and sent through WebSocket messages is to be treated as a single duplex stream of bytes, just like with TCP.

Telegram **официально поддерживает WebSocket-транспорт**. Серверы `pluto.web.telegram.org`, `venus.web.telegram.org` и т.д. — это не просто веб-клиент. Это **полноценные точки входа в сеть Telegram** через WSS.

Схема:

```
Telegram Desktop
       │
       ▼ SOCKS5
┌──────────────────┐
│   TG Unblock     │  127.0.0.1:1080
│   WS-прокси      │
└──────┬───────────┘
       │
       ├── IP Telegram? ──► WSS к {dc}.web.telegram.org/apiws
       │                    (провайдер видит: HTTPS к web.telegram.org)
       │
       └── Другой IP? ────► Прямой TCP (без изменений)
```

Провайдер видит:
- Соединение к `venus.web.telegram.org` по порту 443
- Обычный TLS/HTTPS трафик
- Никакого MTProto

DPI видит:
- Ничего подозрительного
- Обычный WebSocket внутри HTTPS

Результат:
- **Полная скорость** — провайдер не шейпит web.telegram.org
- **Нет переподключений** — DPI не трогает HTTPS
- **Нулевая задержка** — нет промежуточных серверов, трафик идёт напрямую к Telegram

## Реализация: Rust, SOCKS5, WebSocket

### Почему Rust?

Не Electron. Не Python. Не Node.js. **Rust.** Потому что:
- Один бинарник ~6 МБ, без зависимостей
- Нативная скорость — прокси не должен добавлять задержку
- Async I/O через tokio — тысячи одновременных соединений
- Компилируется, запускается, работает

### Архитектура

Приложение состоит из 4 модулей:

| Модуль | Что делает |
|---|---|
| `main.rs` | GUI на egui + управление прокси |
| `ws_proxy.rs` | SOCKS5-сервер + WebSocket-туннель |
| `bypass.rs` | DNS-настройка, системные утилиты |
| `network.rs` | Сетевая диагностика |

### SOCKS5 → WebSocket: как это работает

Когда Telegram Desktop подключается через SOCKS5-прокси, происходит следующее:

**1. SOCKS5 handshake**

```rust
// Клиент: [0x05, 0x01, 0x00] — SOCKS5, 1 метод, no auth
// Сервер: [0x05, 0x00] — принято
// Клиент: [0x05, 0x01, 0x00, 0x01, IP, PORT] — CONNECT к IP:PORT
```

**2. Определение DC по IP**

Telegram использует фиксированные подсети для каждого Data Center. Из [документации](https://core.telegram.org/mtproto/transports):

```rust
fn telegram_dc(ip: Ipv4Addr) -> Option<u8> {
    let o = ip.octets();
    match (o[0], o[1]) {
        (149, 154) => Some(match o[2] {
            160..=163 => 1,  // DC1
            164..=167 => 2,  // DC2
            168..=171 => 3,  // DC3
            172..=175 => 1,  // DC1 alt
            _ => 2,
        }),
        (91, 108) => Some(match o[2] {
            56..=59 => 5,    // DC5
            8..=11 => 3,     // DC3
            12..=15 => 4,    // DC4
            _ => 2,
        }),
        (91, 105) => Some(2),
        (185, 76) => Some(2),
        _ => None,
    }
}
```

**3. WebSocket-туннель**

Каждый DC имеет именованный WebSocket-эндпоинт (имена из официальной документации Telegram):

| DC | Имя | URL |
|---|---|---|
| 1 | Pluto | `wss://pluto.web.telegram.org/apiws` |
| 2 | Venus | `wss://venus.web.telegram.org/apiws` |
| 3 | Aurora | `wss://aurora.web.telegram.org/apiws` |
| 4 | Vesta | `wss://vesta.web.telegram.org/apiws` |
| 5 | Flora | `wss://flora.web.telegram.org/apiws` |

Обязательный заголовок (из доки Telegram): `Sec-WebSocket-Protocol: binary`.

```rust
let mut request = ws_url.as_str().into_client_request()?;
request.headers_mut().insert(
    "Sec-WebSocket-Protocol", "binary".parse()?,
);

let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(
    request, None, false, Some(connector),
).await?;
```

**4. Двунаправленный relay**

Ключевая цитата из документации Telegram:

> All data received and sent through WebSocket messages is to be treated as a **single duplex stream of bytes**, just like with TCP.

Это значит, что нам не нужно парсить MTProto. Просто relay байтов: TCP → WebSocket binary frame, WebSocket binary frame → TCP.

```rust
let up = async {
    let mut buf = vec![0u8; 32768];
    loop {
        match tcp_rx.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let msg = Message::Binary(buf[..n].to_vec());
                if ws_tx.send(msg).await.is_err() { break; }
            }
            Err(_) => break,
        }
    }
};

let down = async {
    while let Some(Ok(msg)) = ws_rx.next().await {
        if let Message::Binary(data) = msg {
            if tcp_tx.write_all(&data).await.is_err() { break; }
        }
    }
};

tokio::select! { _ = up => {}, _ = down => {} }
```

### GUI: egui, не Electron

Нативный GUI через `egui` / `eframe`. Никакого браузера, никакого DOM, никакого JavaScript. Вся отрисовка — immediate mode, 60 FPS.

Кнопка «Запустить обход» делает:
1. Меняет DNS на Cloudflare (1.1.1.1) — обходит DNS-блокировку
2. Запускает SOCKS5-прокси на 127.0.0.1:1080
3. Предлагает автонастройку Telegram через `tg://socks?server=127.0.0.1&port=1080`

Кнопка «Настроить автоматически» — открывает Telegram Desktop с готовой конфигурацией прокси. Один клик.

## Технические детали, которые пришлось решить

### Проблема 1: Не-Telegram трафик

Если Telegram Desktop пускает через SOCKS5 не только MTProto, но и запросы к CDN, стикер-серверам, обновлениям — их нельзя заворачивать в WebSocket. Решение: проверяем IP по маппингу Telegram-подсетей. Telegram IP → WebSocket. Всё остальное → прямой TCP passthrough.

### Проблема 2: Определение DC

Telegram Desktop использует obfuscated2 транспорт. Первые 64 байта — зашифрованный хендшейк, в котором закодирован DC ID. Парсить его — целый проект.

Решение проще: определяем DC по destination IP. Telegram использует фиксированные подсети для каждого DC — маппинг стабильный и документированный.

### Проблема 3: TLS к WebSocket-эндпоинтам

WebSocket-соединение идёт через WSS (TLS). Используем `native-tls` — системные сертификаты Windows, без привязки к OpenSSL.

```rust
let connector = tokio_tungstenite::Connector::NativeTls(
    native_tls::TlsConnector::new()?,
);
```

### Проблема 4: Graceful shutdown

При остановке прокси нужно:
- Сбросить DNS обратно на DHCP
- Корректно закрыть все WebSocket-соединения
- Не оставить Telegram без связи

Используем `AtomicBool` для флага остановки — все задачи проверяют его и завершаются.

## Сравнение с альтернативами

| | GoodbyeDPI | Zapret | VPN | **TG Unblock** |
|---|---|---|---|---|
| Подход | Фрагментация пакетов | Desync пакетов | Туннель через сервер | WebSocket-туннель |
| DPI видит MTProto? | Нет | Нет | Нет | **Нет** |
| IP-шейпинг? | Не обходит | Не обходит | Обходит | **Обходит** |
| Нужен сервер? | Нет | Нет | Да | **Нет** |
| Скорость | Зависит от DPI | Зависит от DPI | Зависит от сервера | **Полная** |
| Весь трафик? | Нет | Нет | Да | **Только Telegram** |
| Стоимость | Бесплатно | Бесплатно | $3–10/мес | **Бесплатно** |

## Стек

| Технология | Зачем |
|---|---|
| **Rust** | Скорость, один бинарник, без зависимостей |
| **egui / eframe** | Нативный GUI без браузера |
| **tokio** | Async I/O, тысячи соединений |
| **tokio-tungstenite** | WebSocket-клиент с TLS |
| **native-tls** | Системные сертификаты Windows |
| **GitHub Actions** | CI/CD — автобилд при новом теге |

## Цифры

- **5 DC** — полный маппинг всех Telegram Data Center
- **1 бинарник** — ~6 МБ, без зависимостей
- **0 серверов** — всё работает локально
- **0₽** — полностью бесплатно и open-source
- **1 клик** — от запуска до работающего Telegram

## Как попробовать

### Скачать готовый .exe

1. Скачайте `tg_unblock.exe` из [Releases](https://github.com/by-sonic/tglock/releases)
2. Запустите (желательно от администратора — для DNS)
3. Нажмите **«Запустить обход»**
4. Нажмите **«Настроить автоматически»**
5. В Telegram нажмите «Подключить»

### Собрать из исходников

```bash
git clone https://github.com/by-sonic/tglock.git
cd tglock
cargo build --release
# Бинарник: target/release/tg_unblock.exe
```

## Что дальше

- **Автоопределение DC из obfuscated2** — парсинг первых 64 байт для точного маппинга
- **Fallback на GoodbyeDPI** — если WebSocket-эндпоинт недоступен
- **Linux / macOS** — porability через tokio + egui (уже почти готово)
- **Статистика** — скорость, задержка, количество туннелей в реальном времени

## Вместо заключения

Telegram — это не просто мессенджер. Для миллионов людей это рабочий инструмент, канал связи, источник информации. Когда он работает через боль — страдают все.

GoodbyeDPI — отличный инструмент, но у него есть потолок. Когда DPI побеждён, а трафик всё равно шейпится — нужен другой подход. WebSocket-туннель через `web.telegram.org` — это как проехать мимо камеры на легальной машине вместо того, чтобы заклеивать номера.

Код полностью открыт. Если пригодился — поставьте звезду на GitHub. Если нашли баг — PR приветствуются.

**GitHub:** [github.com/by-sonic/tglock](https://github.com/by-sonic/tglock)

**P.S.** Если нужен полный обход блокировок для всех приложений (YouTube, Discord, Instagram и др.) — попробуйте [by sonic VPN](https://t.me/bysonicvpn_bot). Быстрый, стабильный, без ограничений скорости.

---

*by sonic*

**Теги:** telegram, dpi bypass, websocket, rust, socks5, mtproto, обход блокировок, open-source

**Хабы:** Rust · Open source · Windows · Сетевые технологии
