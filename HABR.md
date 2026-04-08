# Написал обход блокировки Telegram на Rust за 300 строк — без VPN, серверов и абонентки

**Простой · 6 мин · Rust · Open source · Сетевые технологии · Из песочницы**

**TL;DR:** Open-source приложение **TGLock** на Rust. Один клик — Telegram работает. Локальный SOCKS5-прокси заворачивает MTProto в WebSocket через `web.telegram.org`. Провайдер видит HTTPS. Windows, macOS, Linux. 300 строк кода. GitHub — [by-sonic/tglock](https://github.com/by-sonic/tglock).

---

## Почему GoodbyeDPI больше не хватает

GoodbyeDPI, Zapret — отличные инструменты. Они фрагментируют пакеты, ломают сигнатуры DPI, и это работало. До определённого момента.

Проблема: провайдеры перешли от DPI к **IP-шейпингу**. Весь трафик к подсетям Telegram (149.154.x.x, 91.108.x.x) режется по скорости. Неважно, видит DPI MTProto или нет — если destination IP принадлежит Telegram, соединение троттлится.

Результат: GoodbyeDPI запущен, пакеты фрагментированы, DPI обманут — а Telegram всё равно грузится 10 секунд, медиа не приходят, звонки рвутся. Пинг 200+, постоянные переподключения.

VPN решает, но:
- Стоит денег
- Гонит **весь** трафик через чужой сервер
- Для одного Telegram — оверкилл

Нужен другой подход.

## Идея: WebSocket через web.telegram.org

Замерил: прямое TCP-соединение к серверам Telegram (149.154.167.51:443) — таймаут или 200+ мс. А вот `web.telegram.org` отвечает стабильно за 50–80 мс. Логично: это «обычный сайт», провайдер его не трогает.

Полез в [документацию MTProto](https://core.telegram.org/mtproto/transports):

> **WebSocket:** Implementation of the WebSocket transport is **pretty much the same as with TCP**... all data received and sent through WebSocket messages is to be treated as a **single duplex stream of bytes**, just like with TCP.

Telegram официально поддерживает WebSocket-транспорт. Эндпоинты `kws1-5.web.telegram.org` — полноценные точки входа в сеть Telegram через WSS.

**Схема:**

```
Telegram Desktop → SOCKS5 → TGLock → WSS (kws{dc}.web.telegram.org) → DC
                                ↑
                   Провайдер видит: HTTPS к web.telegram.org
```

Нет MTProto в трафике. Нет подозрительных IP. Обычный HTTPS.

## Реализация: 300 строк на Rust

Весь проект — два файла: `proxy.rs` (туннель) и `main.rs` (UI).

### SOCKS5 → определение DC → WebSocket

Когда Telegram Desktop подключается через SOCKS5, мы:

**1.** Обрабатываем SOCKS5-хендшейк и получаем destination IP.

**2.** Читаем первые 64 байта — это obfuscated2 init-пакет MTProto. Из него извлекаем настоящий DC через AES-256-CTR:

```rust
fn dc_from_init(init: &[u8; 64]) -> Option<u8> {
    use aes::Aes256;
    use cipher::{KeyIvInit, StreamCipher};

    let mut dec = *init;
    let mut c = ctr::Ctr128BE::<Aes256>::new(
        init[8..40].into(),
        init[40..56].into(),
    );
    c.apply_keystream(&mut dec);

    let id = i32::from_le_bytes([dec[60], dec[61], dec[62], dec[63]]);
    let dc = id.unsigned_abs() as u8;
    (1..=5).contains(&dc).then_some(dc)
}
```

**3.** Открываем WebSocket к нужному DC с обязательным заголовком `Sec-WebSocket-Protocol: binary` и таймаутом 10 секунд:

```rust
let (mut ws, _) = tokio::time::timeout(
    Duration::from_secs(10),
    tokio_tungstenite::connect_async_tls_with_config(req, None, false, Some(tls)),
).await??;
```

**4.** Отправляем буферизованные 64 байта init-пакета как первый WebSocket-фрейм. Дальше — двунаправленный relay в одном `tokio::select!` цикле:

```rust
loop {
    tokio::select! {
        biased;
        msg = ws.next() => match msg {
            Some(Ok(Message::Binary(data))) => {
                tcp_w.write_all(data.as_ref()).await?;
                tcp_w.flush().await?;
            }
            Some(Ok(Message::Ping(p))) => {
                ws.send(Message::Pong(p)).await?;
            }
            _ => break,
        },
        n = tcp_r.read(&mut buf) => match n {
            Ok(0) | Err(_) => break,
            Ok(n) => { ws.send(Message::Binary(buf[..n].to_vec())).await?; }
        },
    }
}
```

Ключевой момент — **Ping/Pong**. Без ответа на Ping сервер закрывает соединение через ~2 минуты. Первая версия это игнорировала — пользователи жаловались на обрывы.

### Не-Telegram трафик

Если destination IP не принадлежит Telegram — прямой TCP passthrough. Прокси не трогает ничего лишнего.

## Стабильность: что ломалось и как починили

**Проблема 1: Обрыв через 2 минуты.**
WebSocket-сервер отправляет Ping-фреймы. Первая реализация использовала `split()` и два отдельных потока — Ping приходил в `read`-поток, а Pong нужно было отправить через `write`-поток. Решение: единый `tokio::select!` цикл без split. `biased` приоритизирует WS-чтение — Pong улетает мгновенно.

**Проблема 2: Неправильный DC.**
IP-маппинг ненадёжен: в подсети 149.154.164-167 живут и DC2, и DC4. Если отправить данные не в тот DC — сервер дропает соединение. Решение: извлекать DC из obfuscated2 init через AES-256-CTR.

**Проблема 3: Зависание на подключении.**
Если `kws*.web.telegram.org` не отвечает — прокси висел бесконечно. Решение: `tokio::time::timeout(10s)` на WebSocket connect.

**Проблема 4: Потеря данных.**
TCP-write без `flush()` мог буферизовать данные. Telegram Desktop ожидал ответ, не получал его, переподключался. Решение: явный `flush()` после каждого write.

## UI: egui, не Electron

Нативный GUI через egui. Тёмная тема, минимальный интерфейс. Бинарник ~6 МБ, без зависимостей.

Одна кнопка — ПОДКЛЮЧИТЬ/ОТКЛЮЧИТЬ. Статистика в реальном времени: активные соединения, WebSocket-туннели, текущий DC, аптайм.

## Кроссплатформенность

Ни одной строки платформо-специфичного кода. Работает на:
- **Windows** x64
- **macOS** Intel + Apple Silicon
- **Linux** x64

CI/CD через GitHub Actions — при создании тега автоматически собираются бинарники для всех платформ.

## Сравнение

| | GoodbyeDPI | Zapret | VPN | **TGLock** |
|---|---|---|---|---|
| Метод | Фрагментация | Desync | Туннель | WebSocket |
| Обходит IP-шейпинг | Нет | Нет | Да | **Да** |
| Нужен сервер | Нет | Нет | Да | **Нет** |
| Весь трафик | Нет | Нет | Да | **Только Telegram** |
| Кроссплатформа | Windows | Win/Mac/Linux | Да | **Win/Mac/Linux** |
| Размер | ~1 МБ | ~2 МБ | Зависит | **~6 МБ** |

## Цифры

- **300** строк кода (proxy + UI)
- **2** файла (`proxy.rs` + `main.rs`)
- **3** платформы (Windows, macOS, Linux)
- **0** серверов
- **0₽**

## Скачать

**[github.com/by-sonic/tglock](https://github.com/by-sonic/tglock)** → Releases

Или собрать: `git clone ... && cargo build --release`

**P.S.** Для полного обхода блокировок (YouTube, Discord, Instagram) — **[by sonic VPN](https://t.me/bysonicvpn_bot)**.

---

*by sonic*

**Теги:** telegram, rust, websocket, socks5, mtproto, dpi, обход блокировок, open-source

**Хабы:** Rust · Open source · Сетевые технологии
