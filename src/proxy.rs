use crate::config::ListenConfig;
use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite;

pub const DEFAULT_PORT: u16 = 1080;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const INIT_LEN: usize = 64;
const SOCKS5_VERSION: u8 = 0x05;
/// How long to wait for a full MTProto init before treating an ambiguous first
/// byte as the start of a SOCKS5 greeting.
const PROTOCOL_PROBE_TIMEOUT: Duration = Duration::from_millis(250);
const PROTOCOL_PROBE_INTERVAL: Duration = Duration::from_millis(5);
/// Сколько неотвеченных Ping'ов держать, пока отправляющая половина занята.
const PONG_QUEUE: usize = 4;

pub struct Stats {
    pub running: AtomicBool,
    pub active: AtomicU32,
    pub total: AtomicU32,
    pub ws: AtomicU32,
    /// DC последнего разобранного соединения. Показывается, пока туннеля ещё
    /// нет: клиент уже понят, маршрут ещё не выбран.
    seen_dc: AtomicU16,
    pub ws_failures: AtomicU32,
    /// Сколько запросов отклонено политикой «только Telegram».
    ///
    /// В LAN-режиме это единственный признак, отличающий «телефон не дотянулся
    /// до компьютера» от «дотянулся, но попросил адрес, который мы не пускаем».
    /// Раньше отказ происходил молча, и снаружи оба случая выглядели одинаково
    /// (by-sonic/tglock#42).
    pub blocked: AtomicU32,
    /// Сколько клиентов дошло до прокси, но не сумело договориться.
    ///
    /// Почти всегда это несовпадение секрета: в Telegram вписана ссылка от
    /// прошлого запуска. Такое соединение закрывалось молча, и по диагностике
    /// отличить его от рабочего было нельзя.
    pub unknown_clients: AtomicU32,
    /// Сколько соединений открылось и ничего не прислало за `IO_TIMEOUT`.
    ///
    /// Такое соединение закрывается по таймауту и до сих пор не попадало ни в
    /// один счётчик: `unknown_clients` растёт, только когда запрос пришёл и не
    /// разобрался, а не когда его не дождались. По диагностике это выглядело
    /// как соединение без туннеля и ничего больше — а репортёр #42 видел, что
    /// его телефон переустанавливает соединение примерно раз в десять секунд,
    /// то есть ровно с этим периодом.
    pub silent_clients: AtomicU32,
    /// DC и маршрут последнего поднятого туннеля, упакованные в одно значение.
    ///
    /// Раньше это были два независимых поля: номер писало соединение при
    /// разборе init, маршрут — другое соединение после рукопожатия. При
    /// нескольких десятках одновременных соединений пара в строке статуса
    /// складывалась из разных из них, и читалась она как «до этого DC шли
    /// этим маршрутом», хотя означала совсем не это. У DC1, DC3, DC5 и DC203
    /// закреплённый адрес всего один, и «запасного» у них не бывает вовсе —
    /// а строки `DC5 · Запасной Telegram IP` в диагностике встречались
    /// (by-sonic/tglock#42).
    ///
    /// Формат: `dc << 8 | route`, где route — `transport::RouteKind::ui_code`.
    last_tunnel: AtomicU32,
    transport: crate::transport::TransportEngine,
    secret: [u8; 16],
    /// Почему секрет не удалось сохранить, если не удалось.
    secret_write_error: Option<String>,
    events: Mutex<Events>,
    shutdown: Mutex<Option<tokio::sync::watch::Sender<bool>>>,
}

/// Однократные сообщения о том, что происходит с подключениями.
///
/// Однократные намеренно: отклонённый адрес повторяется десятки раз в минуту,
/// и без склейки журнал превратился бы в одну строку, повторённую сто раз.
/// Число повторов при этом не теряется — оно в счётчике `blocked`.
#[derive(Default)]
struct Events {
    pending: VecDeque<String>,
    seen: HashSet<String>,
}

/// Сколько разных событий помним, чтобы буфер не рос без границы.
const EVENT_LIMIT: usize = 64;

impl Stats {
    pub fn new() -> Arc<Self> {
        Self::with_stored_secret(initial_secret())
    }

    /// Построить с секретом, про который известно, сохранился он на диск или нет.
    ///
    /// Если не сохранился, при следующем запуске ссылка `tg://proxy` изменится и
    /// Telegram скажет «прокси настроен неверно и будет отключён». Раньше это
    /// происходило молча (by-sonic/tglock#37).
    pub fn with_stored_secret(stored: crate::mtproto::StoredSecret) -> Arc<Self> {
        Self::build(stored.value, stored.write_error)
    }

    /// Build with an explicit proxy secret.
    ///
    /// A daemon must pin this: the secret is half of the `tg://proxy` link, so
    /// generating a fresh one on restart breaks every configured client.
    pub fn with_secret(secret: [u8; 16]) -> Arc<Self> {
        Self::build(secret, None)
    }

    /// Сообщение о том, почему секрет не сохранён, если он не сохранён.
    pub fn secret_write_error(&self) -> Option<&str> {
        self.secret_write_error.as_deref()
    }

    fn build(secret: [u8; 16], secret_write_error: Option<String>) -> Arc<Self> {
        Arc::new(Self {
            running: AtomicBool::new(false),
            active: AtomicU32::new(0),
            total: AtomicU32::new(0),
            ws: AtomicU32::new(0),
            seen_dc: AtomicU16::new(0),
            ws_failures: AtomicU32::new(0),
            blocked: AtomicU32::new(0),
            unknown_clients: AtomicU32::new(0),
            silent_clients: AtomicU32::new(0),
            last_tunnel: AtomicU32::new(0),
            transport: crate::transport::TransportEngine::new(),
            secret,
            secret_write_error,
            events: Mutex::new(Events::default()),
            shutdown: Mutex::new(None),
        })
    }

    /// Запомнить событие, если такого ещё не было.
    pub fn note(&self, message: impl Into<String>) {
        let message = message.into();
        let mut events = self.events.lock().unwrap();
        if events.seen.len() >= EVENT_LIMIT || !events.seen.insert(message.clone()) {
            return;
        }
        events.pending.push_back(message);
    }

    /// Забрать накопившиеся события. Показывает их GUI или CLI — тот, кто есть.
    pub fn drain_events(&self) -> Vec<String> {
        self.events.lock().unwrap().pending.drain(..).collect()
    }

    fn note_blocked(&self, destination: &str, port: u16) {
        self.blocked.fetch_add(1, Ordering::Relaxed);
        self.note(format!(
            "Отклонено: {destination}:{port} — адрес не из сетей Telegram"
        ));
    }

    /// Клиент дошёл, но договориться с ним не удалось.
    ///
    /// Раньше такое соединение закрывалось молча: `active` дёргался вверх и
    /// обратно, и всё. По диагностике это неотличимо от «клиент подключился и
    /// работает», хотя означает противоположное (by-sonic/tglock#42).
    fn note_unknown_client(&self, peer: Option<SocketAddr>, reason: &str) {
        self.unknown_clients.fetch_add(1, Ordering::Relaxed);
        let who = match peer {
            Some(peer) => peer.ip().to_string(),
            None => "неизвестный адрес".to_owned(),
        };
        self.note(format!("Клиент {who}: {reason}"));
    }

    /// Клиент открыл соединение и не сказал ничего.
    ///
    /// Отличается от `note_unknown_client` тем, что там запрос пришёл и не
    /// разобрался, а здесь его не дождались. Для клиента, который открывает
    /// соединения про запас, это норма; для клиента, который переоткрывает их
    /// в такт с таймаутом, — нет, и разницу видно только по счётчику
    /// (by-sonic/tglock#42).
    fn note_silent_client(&self, peer: Option<SocketAddr>, reason: &str) {
        self.silent_clients.fetch_add(1, Ordering::Relaxed);
        let who = match peer {
            Some(peer) => peer.ip().to_string(),
            None => "неизвестный адрес".to_owned(),
        };
        self.note(format!(
            "Клиент {who}: {reason} за {} с — соединение закрыто",
            IO_TIMEOUT.as_secs()
        ));
    }

    /// Отметить, что до прокси дотянулось устройство из сети, а не с этой машины.
    ///
    /// Это первое, что нужно знать при разборе LAN-режима: если строки нет,
    /// телефон до компьютера не дошёл, и дело в сети, а не в TGLock.
    fn note_peer(&self, peer: SocketAddr) {
        if peer.ip().is_loopback() {
            return;
        }
        self.note(format!("Подключилось устройство из сети: {}", peer.ip()));
    }

    /// Запомнить DC, с которым пришёл клиент. Туннеля может ещё не быть.
    fn note_dc(&self, dc: u16) {
        self.seen_dc.store(dc, Ordering::Relaxed);
    }

    /// Запомнить, каким маршрутом поднялся туннель и до какого DC.
    ///
    /// Пишется одним значением, чтобы пара в диагностике всегда была из
    /// одного соединения.
    fn note_tunnel(&self, dc: u16, route: u8) {
        self.last_tunnel
            .store(u32::from(dc) << 8 | u32::from(route), Ordering::Relaxed);
    }

    /// Номер дата-центра для показа: из последнего поднятого туннеля, а пока
    /// туннеля не было — из последнего разобранного соединения.
    pub fn last_dc(&self) -> u16 {
        match self.last_tunnel.load(Ordering::Relaxed) {
            0 => self.seen_dc.load(Ordering::Relaxed),
            packed => (packed >> 8) as u16,
        }
    }

    /// Маршрут последнего поднятого туннеля. См. `transport::RouteKind::ui_code`.
    pub fn last_route(&self) -> u8 {
        (self.last_tunnel.load(Ordering::Relaxed) & 0xff) as u8
    }

    pub fn telegram_secret(&self) -> String {
        crate::mtproto::telegram_secret(&self.secret)
    }

    /// Сколько отдельных маршрутов не ответило.
    ///
    /// Отличается от `ws_failures`: тот растёт только когда упали все маршруты
    /// и соединение не состоялось. Этот показывает перебор, который прошёл
    /// незаметно — например, когда закреплённый адрес мёртв, а запасной
    /// работает (by-sonic/tglock#32).
    pub fn route_failures(&self) -> u32 {
        self.transport.route_failures()
    }

    pub fn set_worker_domain(&self, domain: &str) {
        let domains = domain
            .split([',', ';', ' '])
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let result = self.transport.set_worker_domains(&domains);
        // Молчание здесь неотличимо от «воркер работает»: пока строка не
        // попадала в список маршрутов, об этом не сообщалось ничем, и человек
        // считал резервный маршрут настроенным (by-sonic/tglock#50).
        for rejected in &result.rejected {
            self.note(format!(
                "Cloudflare Worker «{rejected}» не похож на имя хоста — маршрут не добавлен.                  Нужно только имя, без https:// и без косой черты: example.workers.dev"
            ));
        }
        for accepted in &result.accepted {
            self.note(format!("Cloudflare Worker в списке маршрутов: {accepted}"));
        }
    }

    pub fn stop(&self) {
        if let Some(sender) = self.shutdown.lock().unwrap().take() {
            let _ = sender.send(true);
        }
    }
}

#[cfg(not(test))]
fn initial_secret() -> crate::mtproto::StoredSecret {
    crate::mtproto::load_or_create_secret()
}

#[cfg(test)]
fn initial_secret() -> crate::mtproto::StoredSecret {
    crate::mtproto::StoredSecret {
        value: crate::mtproto::generate_secret(),
        write_error: None,
    }
}

/// Claim the local port.
///
/// Separated from [`serve`] so a caller can report a port conflict before it
/// tells the user the proxy is running.
pub async fn bind(listen: ListenConfig) -> Result<TcpListener, String> {
    TcpListener::bind(listen.addr)
        .await
        .map_err(|error| format!("Cannot listen on {}: {}", listen.addr, error))
}

/// Bind and serve until [`Stats::stop`] is called.
pub async fn run(stats: Arc<Stats>, listen: ListenConfig) -> Result<(), String> {
    let listener = bind(listen).await?;
    serve(stats, listener, listen.allow_direct).await
}

/// Accept clients on an already bound listener.
pub async fn serve(
    stats: Arc<Stats>,
    listener: TcpListener,
    allow_direct: bool,
) -> Result<(), String> {
    stats.running.store(true, Ordering::SeqCst);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    *stats.shutdown.lock().unwrap() = Some(shutdown_tx);
    let mut tasks = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        let s = stats.clone();
                        s.note_peer(peer);
                        s.active.fetch_add(1, Ordering::Relaxed);
                        s.total.fetch_add(1, Ordering::Relaxed);
                        tasks.spawn(async move {
                            let _ = handle(stream, &s, allow_direct).await;
                            s.active.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(error) => {
                        stats.running.store(false, Ordering::SeqCst);
                        return Err(format!("Accept failed: {}", error));
                    }
                }
            }
            _ = shutdown_rx.changed() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }

    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    stats.active.store(0, Ordering::Relaxed);
    stats.ws.store(0, Ordering::Relaxed);
    stats.running.store(false, Ordering::SeqCst);
    Ok(())
}

// -- SOCKS5 -----------------------------------------------------------------

#[derive(Debug, Eq, PartialEq)]
enum Protocol {
    Socks5,
    MtProto,
    Empty,
}

async fn handle(
    s: TcpStream,
    stats: &Stats,
    allow_direct: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match detect_protocol(&s, stats).await? {
        Protocol::Socks5 => handle_socks5(s, stats, allow_direct).await,
        Protocol::MtProto => handle_mtproto(s, stats).await,
        Protocol::Empty => Ok(()),
    }
}

/// Decide which protocol a fresh client is speaking without consuming anything.
///
/// A SOCKS5 greeting starts with `0x05` — but so does one in every 256 MTProto
/// init packets, because the client fills those 64 bytes at random and
/// `mtproto::is_reserved_init` only avoids `0xef`, `0xee`, `0xdd`, HTTP verbs
/// and the TLS record header. Deciding on the first byte alone therefore sends
/// roughly one connection in 256 down the SOCKS5 path, where it dies. From the
/// outside that looks exactly like Telegram sending messages every other try.
///
/// When the first byte is ambiguous, wait briefly: a real SOCKS5 client sends a
/// short greeting and then blocks on our reply, so only MTProto produces a full
/// 64-byte init that decodes under our secret.
async fn detect_protocol(
    stream: &TcpStream,
    stats: &Stats,
) -> Result<Protocol, Box<dyn std::error::Error + Send + Sync>> {
    let mut probe = [0; INIT_LEN];
    let peeked = match tokio::time::timeout(IO_TIMEOUT, stream.peek(&mut probe[..1])).await {
        Ok(peeked) => peeked?,
        Err(_) => {
            stats.note_silent_client(stream.peer_addr().ok(), "не прислал ни байта");
            return Err("client protocol detection timeout".into());
        }
    };
    if peeked == 0 {
        return Ok(Protocol::Empty);
    }
    if probe[0] != SOCKS5_VERSION {
        return Ok(Protocol::MtProto);
    }

    let deadline = tokio::time::Instant::now() + PROTOCOL_PROBE_TIMEOUT;
    loop {
        if stream.peek(&mut probe).await? == INIT_LEN {
            return Ok(
                if crate::mtproto::parse_client_init(&probe, &stats.secret).is_some() {
                    Protocol::MtProto
                } else {
                    Protocol::Socks5
                },
            );
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(Protocol::Socks5);
        }
        tokio::time::sleep(PROTOCOL_PROBE_INTERVAL).await;
    }
}

/// Куда просится SOCKS5-клиент и что с этим делать.
#[derive(Debug, Eq, PartialEq)]
enum Destination {
    /// Адрес дата-центра Telegram: дальше идёт MTProto, его заворачиваем в
    /// WebSocket — ради этого TGLock и существует.
    DataCentre(IpAddr),
    /// Имя из веб-инфраструктуры Telegram. Это обычный HTTPS, а не MTProto:
    /// клиент ходит сюда за конфигурацией, превью и файлами CDN. Заворачивать
    /// такое соединение в MTProto-туннель нельзя, его нужно пропустить как есть.
    ///
    /// На телефоне эти запросы идут через тот же прокси, поэтому в LAN-режиме
    /// они разрешены — иначе клиент не может даже дочитать свою конфигурацию.
    TelegramWeb,
    /// Всё остальное. На loopback пропускается напрямую, на сетевом адресе —
    /// отклоняется, иначе LAN-режим стал бы открытым прокси.
    Elsewhere,
}

fn classify(address: &str) -> Destination {
    match address.parse::<IpAddr>() {
        Ok(ip) if crate::telegram_net::is_telegram(ip) => Destination::DataCentre(ip),
        Ok(_) => Destination::Elsewhere,
        Err(_) if crate::telegram_net::is_telegram_host(address) => Destination::TelegramWeb,
        Err(_) => Destination::Elsewhere,
    }
}

async fn handle_socks5(
    mut s: TcpStream,
    stats: &Stats,
    allow_direct: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    s.set_nodelay(true)?;
    let peer = s.peer_addr().ok();

    let request = tokio::time::timeout(IO_TIMEOUT, read_socks5_request(&mut s))
        .await
        .map_err(|_| "SOCKS5 handshake timeout".to_owned())
        .and_then(|result| result.map_err(|error| error.to_string()));
    let (addr, port) = match request {
        Ok(request) => request,
        Err(error) => {
            stats.note_unknown_client(peer, &format!("SOCKS5-приветствие не разобрано ({error})"));
            return Err(error.into());
        }
    };
    let destination = classify(&addr);
    if destination == Destination::Elsewhere && !allow_direct {
        stats.note_blocked(&addr, port);
        write_socks_reply(&mut s, 0x02).await?;
        return Err("LAN mode only permits Telegram destinations".into());
    }

    // success reply
    s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38])
        .await?;

    if let Destination::DataCentre(ip) = destination {
        // Read 64-byte obfuscated2 init → extract real DC
        let mut init = [0u8; 64];
        s.read_exact(&mut init).await?;

        let (dc, media) = dc_from_init(&init)
            .unwrap_or_else(|| (crate::telegram_net::dc_from_ip(ip).unwrap_or(2), false));

        stats.note_dc(dc);

        let r = ws_tunnel(s, dc, media, &init, None, stats).await;

        if r.is_err() {
            stats.ws_failures.fetch_add(1, Ordering::Relaxed);
        }
        r?;
    } else {
        let remote = tokio::time::timeout(IO_TIMEOUT, connect_direct(&addr, port, allow_direct))
            .await
            .map_err(|_| "direct connection timeout")??;
        let _ = remote.set_nodelay(true);
        tcp_relay(s, remote).await;
    }
    Ok(())
}

/// Открыть прямое соединение по адресу, который назвал клиент.
///
/// В ограниченном режиме имя разрешается заранее и проверяется, куда оно
/// указывает: список доменов принадлежит Telegram, но DNS-ответ приходит извне,
/// а адрес назначения выбирает чужое устройство. Без проверки ответ вида
/// `127.0.0.1` или `192.168.0.1` сделал бы TGLock дверью во внутреннюю сеть
/// этой машины.
async fn connect_direct(
    address: &str,
    port: u16,
    allow_direct: bool,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    if allow_direct {
        return Ok(TcpStream::connect((address, port)).await?);
    }

    let mut last = None;
    for candidate in tokio::net::lookup_host((address, port)).await? {
        if is_private(candidate.ip()) {
            continue;
        }
        match TcpStream::connect(candidate).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last = Some(error),
        }
    }
    Err(match last {
        Some(error) => Box::new(error) as Box<dyn std::error::Error + Send + Sync>,
        None => format!("{address} resolves only to addresses inside this network").into(),
    })
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || ip.octets()[0] == 0
                // 100.64.0.0/10, операторский NAT
                || (ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]))
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                // fc00::/7 — уникальные локальные, fe80::/10 — link-local
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
                || ip.to_ipv4_mapped().is_some_and(|ip| is_private(IpAddr::V4(ip)))
        }
    }
}

async fn handle_mtproto(
    mut stream: TcpStream,
    stats: &Stats,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    stream.set_nodelay(true)?;
    let peer = stream.peer_addr().ok();
    let mut init = [0; 64];
    match tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut init)).await {
        Ok(result) => {
            result?;
        }
        Err(_) => {
            stats.note_silent_client(peer, "начал MTProto-init и не дослал его");
            return Err("MTProto init timeout".into());
        }
    }
    let parsed = match crate::mtproto::parse_client_init(&init, &stats.secret) {
        Some(parsed) => parsed,
        None => {
            // Секрет — половина ссылки `tg://proxy`. Клиент с сохранённой
            // ссылкой от прошлого запуска попадает ровно сюда, и Telegram
            // показывает ему «прокси настроен неверно».
            stats.note_unknown_client(
                peer,
                "MTProto-init не разобран. Скорее всего в Telegram вписан другой \
                 секрет — сверьте ссылку tg://proxy с той, что показана сейчас",
            );
            return Err("invalid MTProto init or secret".into());
        }
    };

    stats.note_dc(parsed.dc);
    let result = ws_tunnel(
        stream,
        parsed.dc,
        parsed.media,
        &parsed.relay_init,
        Some(parsed.crypto),
        stats,
    )
    .await;
    if result.is_err() {
        stats.ws_failures.fetch_add(1, Ordering::Relaxed);
    }
    result
}

async fn read_socks5_request<S>(
    stream: &mut S,
) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = stream.read_u8().await?;
    let method_count = stream.read_u8().await? as usize;
    if version != 0x05 || method_count == 0 {
        return Err("invalid SOCKS5 greeting".into());
    }

    let mut methods = vec![0; method_count];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xff]).await?;
        return Err("SOCKS5 client does not support no-auth mode".into());
    }
    stream.write_all(&[0x05, 0x00]).await?;

    let version = stream.read_u8().await?;
    let command = stream.read_u8().await?;
    let reserved = stream.read_u8().await?;
    let address_type = stream.read_u8().await?;
    if version != 0x05 || reserved != 0 {
        return Err("invalid SOCKS5 request".into());
    }
    if command != 0x01 {
        write_socks_reply(stream, 0x07).await?;
        return Err("unsupported SOCKS5 command".into());
    }

    let address = match address_type {
        0x01 => {
            let mut octets = [0; 4];
            stream.read_exact(&mut octets).await?;
            Ipv4Addr::from(octets).to_string()
        }
        0x03 => {
            let length = stream.read_u8().await? as usize;
            if length == 0 {
                return Err("empty SOCKS5 domain".into());
            }
            let mut domain = vec![0; length];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain)?
        }
        0x04 => {
            let mut octets = [0; 16];
            stream.read_exact(&mut octets).await?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => {
            write_socks_reply(stream, 0x08).await?;
            return Err("unsupported SOCKS5 address type".into());
        }
    };
    let port = stream.read_u16().await?;
    Ok((address, port))
}

async fn write_socks_reply<S>(stream: &mut S, status: u8) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[0x05, status, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
        .await
}

// -- DC detection -----------------------------------------------------------

fn dc_from_init(init: &[u8; 64]) -> Option<(u16, bool)> {
    use aes::Aes256;
    use cipher::{KeyIvInit, StreamCipher};
    type Ctr = ctr::Ctr128BE<Aes256>;

    let mut dec = *init;
    let mut c = Ctr::new(init[8..40].into(), init[40..56].into());
    c.apply_keystream(&mut dec);

    let id = i16::from_le_bytes([dec[60], dec[61]]);
    let dc = id.unsigned_abs();
    matches!(dc, 1..=5 | 203).then_some((dc, id < 0))
}

// -- WebSocket tunnel -------------------------------------------------------

/// Keeps `Stats::ws` equal to the number of *established* tunnels.
///
/// Counting attempts instead would let the interface announce «Telegram на
/// связи» while the WebSocket handshake is still failing over between routes,
/// which takes seconds per route. Reporting a working tunnel that does not
/// exist yet is the whole reason users saw «прокси подключён, а Telegram не
/// работает».
struct EstablishedTunnel<'a>(&'a Stats);

impl<'a> EstablishedTunnel<'a> {
    fn new(stats: &'a Stats) -> Self {
        stats.ws.fetch_add(1, Ordering::Relaxed);
        Self(stats)
    }
}

impl Drop for EstablishedTunnel<'_> {
    fn drop(&mut self) {
        self.0.ws.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn ws_tunnel(
    tcp: TcpStream,
    dc: u16,
    media: bool,
    init: &[u8; 64],
    crypto: Option<crate::mtproto::CryptoContext>,
    stats: &Stats,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures_util::{SinkExt, StreamExt};

    let (ws, connected) = match stats.transport.connect(dc, media).await {
        Ok(connected) => connected,
        Err(error) => {
            // Единственное место, где известно, ПОЧЕМУ туннеля нет. Раньше
            // текст уходил в `Err` и там пропадал: оставался счётчик сбоев без
            // причины, и отличить «провайдер режет адреса» от «воркер отвечает
            // отказом» было нечем (by-sonic/tglock#50).
            stats.note(error.clone());
            return Err(error.into());
        }
    };
    let _tunnel = EstablishedTunnel::new(stats);
    stats.note_tunnel(dc, connected.route.kind.ui_code());

    let (mut tcp_r, mut tcp_w) = tokio::io::split(tcp);
    let (mut ws_w, mut ws_r) = ws.split();
    let (upstream_crypto, downstream_crypto) = match crypto.map(|crypto| crypto.split()) {
        Some((upstream, downstream)) => (Some(upstream), Some(downstream)),
        None => (None, None),
    };

    // Send buffered init as first frame
    ws_w.send(tungstenite::Message::Binary(init.to_vec()))
        .await?;

    // Ping приходит в половину, которая читает, а отвечать на него должна та,
    // которая пишет: владелец у отправляющей половины строго один.
    let (pong_tx, mut pong_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(PONG_QUEUE);

    // Направления работают независимо друг от друга. Раньше это был один
    // `select!`, и любое ожидание внутри него останавливало вторую половину:
    // непрерывная загрузка не давала опросить клиента вообще, а клиент,
    // который не успевал разбирать входящий поток, замораживал заодно и свою
    // отправку. Telegram при этом ждёт от клиента подтверждений — без них
    // сессия встаёт при живом туннеле (by-sonic/tglock#42, #32).
    let downstream = async {
        let mut crypto = downstream_crypto;
        while let Some(message) = ws_r.next().await {
            match message {
                Ok(tungstenite::Message::Binary(mut data)) => {
                    if let Some(crypto) = &mut crypto {
                        crypto.apply(data.as_mut());
                    }
                    tcp_w.write_all(data.as_ref()).await?;
                    tcp_w.flush().await?;
                }
                Ok(tungstenite::Message::Ping(payload)) => {
                    if pong_tx.send(payload).await.is_err() {
                        break;
                    }
                }
                Ok(tungstenite::Message::Close(_)) | Err(_) => break,
                Ok(_) => {}
            }
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };

    let upstream = async {
        let mut crypto = upstream_crypto;
        let mut buf = vec![0u8; 65536];
        loop {
            tokio::select! {
                read = tcp_r.read(&mut buf) => match read {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        if let Some(crypto) = &mut crypto {
                            crypto.apply(&mut buf[..read]);
                        }
                        ws_w
                            .send(tungstenite::Message::Binary(buf[..read].to_vec()))
                            .await?;
                    }
                },
                payload = pong_rx.recv() => match payload {
                    Some(payload) => {
                        ws_w.send(tungstenite::Message::Pong(payload)).await?;
                    }
                    None => break,
                },
            }
        }
        let _ = ws_w.close().await;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };

    tokio::pin!(downstream, upstream);
    tokio::select! {
        result = &mut downstream => result?,
        result = &mut upstream => result?,
    }
    Ok(())
}

async fn tcp_relay(a: TcpStream, b: TcpStream) {
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    tokio::select! {
        _ = tokio::io::copy(&mut ar, &mut bw) => {}
        _ = tokio::io::copy(&mut br, &mut aw) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
    use tokio_tungstenite::tungstenite::Message;

    /// Start the proxy on a kernel-assigned port.
    ///
    /// Binding first and reading the port back removes the reserve-then-rebind
    /// race that a `port 0` helper would otherwise introduce.
    async fn start_proxy(
        stats: Arc<Stats>,
        allow_direct: bool,
    ) -> (u16, tokio::task::JoinHandle<Result<(), String>>) {
        let listener = bind(ListenConfig::loopback(0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { serve(stats, listener, allow_direct).await });
        (port, server)
    }

    async fn wait_until(label: &str, mut condition: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {label}"));
    }

    /// Perform a SOCKS5 greeting, send `request`, return the 10-byte reply.
    async fn socks5_exchange(port: u16, request: &[u8]) -> (TcpStream, [u8; 10]) {
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greeting = [0; 2];
        client.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [0x05, 0x00]);
        client.write_all(request).await.unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        (client, reply)
    }

    fn socks5_ipv4_request(command: u8, ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut request = vec![0x05, command, 0x00, 0x01];
        request.extend_from_slice(&ip);
        request.extend_from_slice(&port.to_be_bytes());
        request
    }

    /// A client init whose first byte is not the SOCKS5 version, so the test
    /// exercises the unambiguous detection path.
    fn unambiguous_client_init(secret: &[u8; 16], dc_index: i16) -> [u8; INIT_LEN] {
        loop {
            let init = crate::mtproto::test_client_init(secret, dc_index);
            if init[0] != SOCKS5_VERSION {
                return init;
            }
        }
    }

    fn ambiguous_client_init(secret: &[u8; 16], dc_index: i16) -> [u8; INIT_LEN] {
        loop {
            let init = crate::mtproto::test_client_init(secret, dc_index);
            if init[0] == SOCKS5_VERSION {
                return init;
            }
        }
    }

    /// Stand-in for `kwsN.web.telegram.org`: a plaintext WebSocket that behaves
    /// like an obfuscated2 relay.
    ///
    /// Returns the URI it was asked for, the raw init frame it was handed and
    /// the plaintext it recovered, so a test can assert on what Telegram — or a
    /// Cloudflare Worker standing in for it — would really have seen.
    // The handshake callback's error type is tungstenite's own `ErrorResponse`,
    // whose size is not ours to change.
    #[allow(clippy::result_large_err)]
    async fn mock_relay(
        listener: TcpListener,
        response: Vec<u8>,
    ) -> Result<(String, Vec<u8>, Vec<u8>), String> {
        use futures_util::{SinkExt, StreamExt};

        let (tcp, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let requested = Arc::new(Mutex::new(String::new()));
        let seen = requested.clone();
        // Telegram confirms the `binary` subprotocol the proxy asks for, and
        // tungstenite refuses a handshake that silently drops it. A mock that
        // does not answer it would only ever test the failure path.
        let mut websocket = tokio_tungstenite::accept_hdr_async(
            tcp,
            move |request: &Request, mut response: Response| {
                *seen.lock().unwrap() = request.uri().to_string();
                response.headers_mut().insert(
                    "Sec-WebSocket-Protocol",
                    "binary".parse().expect("static header value"),
                );
                Ok(response)
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        let requested = requested.lock().unwrap().clone();

        let init = match websocket.next().await {
            Some(Ok(Message::Binary(data))) => data,
            other => return Err(format!("expected an init frame, got {other:?}")),
        };
        let header: [u8; INIT_LEN] = init
            .as_slice()
            .try_into()
            .map_err(|_| format!("init frame is {} bytes, not {INIT_LEN}", init.len()))?;
        let mut relay = crate::mtproto::test_relay_peer(&header);

        let mut request = Vec::new();
        while request.is_empty() {
            match websocket.next().await {
                Some(Ok(Message::Binary(mut data))) => {
                    relay.decrypt(&mut data);
                    request.extend_from_slice(&data);
                }
                Some(Ok(_)) => {}
                _ => break,
            }
        }

        let mut wire = response;
        relay.encrypt(&mut wire);
        websocket
            .send(Message::Binary(wire))
            .await
            .map_err(|e| e.to_string())?;
        Ok((requested, init, request))
    }

    #[tokio::test]
    async fn parses_fragmented_ipv4_socks5_handshake() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let server_task =
            tokio::spawn(async move { read_socks5_request(&mut server).await.unwrap() });

        for part in [&[0x05][..], &[0x01, 0x00]] {
            client.write_all(part).await.unwrap();
            tokio::task::yield_now().await;
        }
        let mut method_reply = [0; 2];
        client.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [0x05, 0x00]);

        for byte in [0x05, 0x01, 0x00, 0x01, 149, 154, 167, 50, 0x01, 0xbb] {
            client.write_all(&[byte]).await.unwrap();
            tokio::task::yield_now().await;
        }

        assert_eq!(
            server_task.await.unwrap(),
            ("149.154.167.50".to_owned(), 443)
        );
    }

    #[tokio::test]
    async fn rejects_auth_only_clients() {
        let (mut client, mut server) = tokio::io::duplex(16);
        let server_task =
            tokio::spawn(async move { read_socks5_request(&mut server).await.is_err() });
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut reply = [0; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0xff]);
        assert!(server_task.await.unwrap());
    }

    /// Что именно решает судьбу соединения в LAN-режиме.
    ///
    /// Принадлежность адреса сетям Telegram проверяется в `telegram_net`;
    /// здесь важно, что из неё следует для каждой из трёх веток.
    #[test]
    fn destinations_are_sorted_into_three_kinds() {
        assert_eq!(
            classify("149.154.167.51"),
            Destination::DataCentre("149.154.167.51".parse().unwrap())
        );
        assert_eq!(
            classify("2001:67c:4e8:f002::a"),
            Destination::DataCentre("2001:67c:4e8:f002::a".parse().unwrap()),
            "IPv6-адрес дата-центра — такой же Telegram (by-sonic/tglock#42)"
        );
        assert_eq!(classify("web.telegram.org"), Destination::TelegramWeb);
        assert_eq!(classify("1.1.1.1"), Destination::Elsewhere);
        assert_eq!(
            classify("185.76.150.1"),
            Destination::Elsewhere,
            "соседний адрес вне опубликованного блока Telegram"
        );
        assert_eq!(classify("telegram.org.example.com"), Destination::Elsewhere);
    }

    #[test]
    fn a_refused_destination_is_counted_and_named_once() {
        let stats = Stats::new();
        for _ in 0..3 {
            stats.note_blocked("1.1.1.1", 443);
        }
        stats.note_blocked("8.8.8.8", 443);

        assert_eq!(
            stats.blocked.load(Ordering::Relaxed),
            4,
            "счётчик считает все отказы"
        );
        let events = stats.drain_events();
        assert_eq!(events.len(), 2, "а журнал называет каждый адрес один раз");
        assert!(events[0].contains("1.1.1.1:443"), "{events:?}");
        assert!(
            stats.drain_events().is_empty(),
            "забранное событие не приходит повторно"
        );
    }

    /// Диагностика обязана показывать пару из одного соединения.
    ///
    /// Пока это были два независимых поля, при десятках одновременных
    /// соединений в строку статуса попадали номер от одного и маршрут от
    /// другого. Читалось это как «до DC5 шли запасным адресом», хотя у DC5
    /// закреплённый адрес всего один и запасного не бывает вовсе
    /// (by-sonic/tglock#42).
    #[test]
    fn the_reported_data_centre_and_route_come_from_the_same_tunnel() {
        let stats = Stats::new();
        assert_eq!(stats.last_dc(), 0, "до соединений показывать нечего");
        assert_eq!(stats.last_route(), 0);

        stats.note_dc(2);
        assert_eq!(stats.last_dc(), 2, "клиент разобран, номер известен");
        assert_eq!(stats.last_route(), 0, "а маршрут ещё не выбран");

        stats.note_tunnel(4, 2);
        assert_eq!((stats.last_dc(), stats.last_route()), (4, 2));

        // Ещё одно соединение до другого DC, туннеля у него пока нет.
        stats.note_dc(203);
        assert_eq!(
            (stats.last_dc(), stats.last_route()),
            (4, 2),
            "пара обязана остаться от соединения, у которого туннель был"
        );
    }

    /// Клиент с сохранённой ссылкой от прошлого запуска. Раньше его соединение
    /// закрывалось молча, и по диагностике это было неотличимо от рабочего.
    #[tokio::test]
    async fn a_client_with_the_wrong_secret_gets_named_instead_of_dropped_in_silence() {
        let stats = Stats::new();
        let (port, server) = start_proxy(stats.clone(), true).await;

        let stranger = crate::mtproto::generate_secret();
        let init = unambiguous_client_init(&stranger, 2);
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&init).await.unwrap();

        wait_until("отказ по секрету", || {
            stats.unknown_clients.load(Ordering::Relaxed) > 0
        })
        .await;
        let events = stats.drain_events();
        assert!(
            events
                .iter()
                .any(|event| event.contains("MTProto-init не разобран")),
            "в журнале должно быть сказано, что init не разобран: {events:?}"
        );

        stats.stop();
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn a_client_that_speaks_neither_protocol_is_counted_too() {
        let stats = Stats::new();
        let (port, server) = start_proxy(stats.clone(), true).await;

        // Приветствие SOCKS5 с нулём методов: разбор обязан провалиться.
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&[0x05, 0x00]).await.unwrap();

        wait_until("отказ по рукопожатию", || {
            stats.unknown_clients.load(Ordering::Relaxed) > 0
        })
        .await;
        assert!(stats
            .drain_events()
            .iter()
            .any(|event| event.contains("SOCKS5-приветствие не разобрано")));

        stats.stop();
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn stops_listener_and_active_tasks_cleanly() {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);

        let stats = Stats::new();
        let server_stats = stats.clone();
        let server =
            tokio::spawn(async move { run(server_stats, ListenConfig::loopback(port)).await });

        tokio::time::timeout(Duration::from_secs(2), async {
            while !stats.running.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        stats.stop();
        assert!(tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .is_ok());
        assert!(!stats.running.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn parses_domain_and_ipv6_socks5_targets() {
        let domain = "web.telegram.org";
        let mut domain_payload = vec![u8::try_from(domain.len()).unwrap()];
        domain_payload.extend_from_slice(domain.as_bytes());

        for (address_type, payload, expected) in
            [(0x03_u8, domain_payload, domain), (0x04, vec![0; 16], "::")]
        {
            let (mut client, mut server) = tokio::io::duplex(256);
            let task = tokio::spawn(async move { read_socks5_request(&mut server).await.unwrap() });

            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut greeting = [0; 2];
            client.read_exact(&mut greeting).await.unwrap();

            let mut request = vec![0x05, 0x01, 0x00, address_type];
            request.extend_from_slice(&payload);
            request.extend_from_slice(&443_u16.to_be_bytes());
            client.write_all(&request).await.unwrap();

            assert_eq!(task.await.unwrap(), (expected.to_owned(), 443));
        }
    }

    #[tokio::test]
    async fn rejects_malformed_and_unsupported_socks5_requests() {
        // (request after the greeting, expected reply status, why)
        let cases: [(Vec<u8>, Option<u8>, &str); 5] = [
            (
                vec![0x05, 0x03, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xbb],
                Some(0x07),
                "UDP ASSOCIATE is not implemented, so it must be refused rather than half-served",
            ),
            (
                vec![0x05, 0x02, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xbb],
                Some(0x07),
                "BIND is not implemented",
            ),
            (
                vec![0x05, 0x01, 0x00, 0x09, 1, 1, 1, 1, 0x01, 0xbb],
                Some(0x08),
                "unknown address type",
            ),
            (
                vec![0x05, 0x01, 0x00, 0x03, 0x00, 0x01, 0xbb],
                None,
                "empty domain",
            ),
            (
                vec![0x04, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xbb],
                None,
                "wrong protocol version in the request",
            ),
        ];

        for (request, expected_status, reason) in cases {
            let (mut client, mut server) = tokio::io::duplex(256);
            let task = tokio::spawn(async move { read_socks5_request(&mut server).await.is_err() });

            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut greeting = [0; 2];
            client.read_exact(&mut greeting).await.unwrap();
            client.write_all(&request).await.unwrap();

            if let Some(status) = expected_status {
                let mut reply = [0; 10];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply[0], 0x05, "{reason}");
                assert_eq!(reply[1], status, "{reason}");
            }
            assert!(task.await.unwrap(), "{reason}");
        }
    }

    #[tokio::test]
    async fn reports_a_busy_port_instead_of_pretending_to_run() {
        let taken = bind(ListenConfig::loopback(0)).await.unwrap();
        let port = taken.local_addr().unwrap().port();

        let error = bind(ListenConfig::loopback(port)).await.unwrap_err();
        assert!(
            error.contains(&port.to_string()),
            "the error must name the port that is busy, got {error:?}"
        );
    }

    #[tokio::test]
    async fn mtproto_init_beginning_with_the_socks5_version_is_not_misrouted() {
        // One init in 256 starts with 0x05. Routing it to the SOCKS5 handler is
        // what makes Telegram work only every other attempt.
        let stats = Stats::new();
        let init = ambiguous_client_init(&stats.secret, 2);
        let (port, server) = start_proxy(stats.clone(), true).await;
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&init).await.unwrap();

        // Detection must land on MTProto, which records the data centre. The
        // SOCKS5 path would instead answer with a handshake reply.
        wait_until("the MTProto data centre to be recorded", || {
            stats.last_dc() == 2
        })
        .await;

        stats.stop();
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn fragmented_socks5_greeting_is_still_detected() {
        let stats = Stats::new();
        let (port, server) = start_proxy(stats.clone(), true).await;

        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        // Byte-at-a-time, the way a small greeting can actually arrive.
        for byte in [0x05, 0x01, 0x00] {
            client.write_all(&[byte]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let mut greeting = [0; 2];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut greeting))
            .await
            .expect("the proxy must answer the greeting")
            .unwrap();
        assert_eq!(greeting, [0x05, 0x00]);

        stats.stop();
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn network_listener_refuses_non_telegram_destinations() {
        let stats = Stats::new();
        let (port, server) = start_proxy(stats.clone(), false).await;

        let (_client, reply) =
            socks5_exchange(port, &socks5_ipv4_request(0x01, [1, 1, 1, 1], 443)).await;
        assert_eq!(
            reply[1], 0x02,
            "a shared listener must not relay arbitrary destinations"
        );
        assert_eq!(
            stats.blocked.load(Ordering::Relaxed),
            1,
            "отказ должен быть виден в диагностике, а не только клиенту"
        );
        assert!(
            stats
                .drain_events()
                .iter()
                .any(|event| event.contains("1.1.1.1:443")),
            "в журнале должен быть назван адрес, из-за которого отказали"
        );

        stats.stop();
        let _ = server.await.unwrap();
    }

    /// Ровно то, на чём ломался LAN-режим: телефон просит адрес дата-центра по
    /// IPv6, а прокси отвечает «не Telegram» (by-sonic/tglock#42).
    #[tokio::test]
    async fn network_listener_accepts_a_telegram_ipv6_data_centre() {
        let stats = Stats::new();
        let (port, server) = start_proxy(stats.clone(), false).await;

        let mut request = vec![0x05, 0x01, 0x00, 0x04];
        request.extend_from_slice(
            &"2001:67c:4e8:f002::a"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        request.extend_from_slice(&443_u16.to_be_bytes());

        let (_client, reply) = socks5_exchange(port, &request).await;
        assert_eq!(reply[1], 0x00, "адрес Telegram по IPv6 нельзя отклонять");
        assert_eq!(stats.blocked.load(Ordering::Relaxed), 0);

        stats.stop();
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn loopback_listener_relays_direct_destinations() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut buffer = [0; 5];
            stream.read_exact(&mut buffer).await.unwrap();
            stream.write_all(&buffer).await.unwrap();
        });

        let stats = Stats::new();
        let (port, server) = start_proxy(stats.clone(), true).await;

        let (mut client, reply) =
            socks5_exchange(port, &socks5_ipv4_request(0x01, [127, 0, 0, 1], echo_port)).await;
        assert_eq!(reply[1], 0x00);

        client.write_all(b"hello").await.unwrap();
        let mut echoed = [0; 5];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");

        stats.stop();
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn tunnels_mtproto_through_a_websocket_relay() {
        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_port = relay_listener.local_addr().unwrap().port();
        let response = b"a reply that only Telegram could have sent".to_vec();
        let relay = tokio::spawn(mock_relay(relay_listener, response.clone()));

        let stats = Stats::new();
        stats.transport.force_local_route(relay_port);
        let (port, server) = start_proxy(stats.clone(), false).await;

        let init = unambiguous_client_init(&stats.secret, -4);
        let mut peer = crate::mtproto::test_client_peer(&init, &stats.secret);
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&init).await.unwrap();

        let request = b"a request that must reach Telegram unchanged".to_vec();
        let mut wire = request.clone();
        peer.encrypt(&mut wire);
        client.write_all(&wire).await.unwrap();

        let mut received = vec![0; response.len()];
        tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut received))
            .await
            .expect("the relay's answer must come back through the tunnel")
            .unwrap();
        peer.decrypt(&mut received);
        assert_eq!(
            received, response,
            "the client must see Telegram's plaintext"
        );

        let (_, init_frame, relayed) = relay.await.unwrap().unwrap();
        assert_eq!(init_frame.len(), INIT_LEN);
        assert_ne!(
            init_frame.as_slice(),
            init.as_slice(),
            "the upstream init must be freshly generated, not the client's own"
        );
        assert_eq!(
            relayed, request,
            "Telegram must receive exactly the client's plaintext"
        );

        assert_eq!(stats.last_dc(), 4);
        assert_eq!(
            stats.last_route(),
            crate::transport::RouteKind::TelegramIp.ui_code()
        );
        assert_eq!(stats.ws_failures.load(Ordering::Relaxed), 0);

        stats.stop();
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn connects_through_the_documented_worker_contract() {
        // Locks the contract in docs/CLOUDFLARE_WORKER.md: a server that
        // implements exactly what is documented there must carry a working
        // tunnel, and must be asked for exactly the documented URI.
        let dc = 2;
        let path = crate::transport::worker_path(dc).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let worker_port = listener.local_addr().unwrap().port();
        let response = b"an answer relayed by the worker".to_vec();
        let worker = tokio::spawn(mock_relay(listener, response.clone()));

        let stats = Stats::new();
        stats.transport.force_local_route_with(
            worker_port,
            crate::transport::RouteKind::CloudflareWorker,
            path.clone(),
        );
        let (port, server) = start_proxy(stats.clone(), false).await;

        let init = unambiguous_client_init(&stats.secret, dc as i16);
        let mut peer = crate::mtproto::test_client_peer(&init, &stats.secret);
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&init).await.unwrap();

        let request = b"a request relayed to the worker".to_vec();
        let mut wire = request.clone();
        peer.encrypt(&mut wire);
        client.write_all(&wire).await.unwrap();

        let mut received = vec![0; response.len()];
        tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut received))
            .await
            .expect("the worker's answer must come back through the tunnel")
            .unwrap();
        peer.decrypt(&mut received);
        assert_eq!(received, response);

        let (requested, _, relayed) = worker.await.unwrap().unwrap();
        assert_eq!(
            requested, path,
            "a deployed worker must serve exactly the documented path and query"
        );
        assert_eq!(relayed, request);
        assert_eq!(
            stats.last_route(),
            crate::transport::RouteKind::CloudflareWorker.ui_code()
        );

        stats.stop();
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn a_tunnel_counts_only_after_the_handshake_succeeds() {
        // Accepts TCP and then stays silent, so the WebSocket handshake never
        // completes: the proxy is mid-attempt and no tunnel exists.
        let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_port = silent.local_addr().unwrap().port();
        let held = tokio::spawn(async move {
            let accepted = silent.accept().await;
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(accepted);
        });

        let stats = Stats::new();
        stats.transport.force_local_route(relay_port);
        let (port, server) = start_proxy(stats.clone(), false).await;

        let init = unambiguous_client_init(&stats.secret, 2);
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&init).await.unwrap();

        wait_until("the init to be parsed", || stats.last_dc() == 2).await;
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(
            stats.ws.load(Ordering::Relaxed),
            0,
            "a handshake still in flight must not be reported as a working tunnel"
        );
        assert_eq!(
            stats.last_route(),
            0,
            "no route may be announced before a tunnel is established"
        );

        stats.stop();
        held.abort();
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn counts_a_failure_when_no_route_answers() {
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);

        let stats = Stats::new();
        stats.transport.force_local_route(dead_port);
        let (port, server) = start_proxy(stats.clone(), false).await;

        let init = unambiguous_client_init(&stats.secret, 2);
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&init).await.unwrap();

        wait_until("the failed tunnel to be counted", || {
            stats.ws_failures.load(Ordering::Relaxed) > 0
        })
        .await;
        assert_eq!(
            stats.last_route(),
            0,
            "a route must not be reported as working when every attempt failed"
        );
        assert_eq!(stats.ws.load(Ordering::Relaxed), 0);

        stats.stop();
        let _ = server.await.unwrap();
    }

    /// Диагностика обязана называть причину, а не только считать сбои.
    ///
    /// При `туннелей 0` счётчик сбоев говорит, что не получилось, и молчит о
    /// том, почему. Текст ошибки собирался и выбрасывался, и разобрать
    /// «провайдер режет адреса» против «воркер отвечает отказом» было нечем
    /// (by-sonic/tglock#50).
    #[tokio::test]
    async fn a_cascade_that_failed_says_why_in_the_log() {
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);

        let stats = Stats::new();
        stats.transport.force_local_route(dead_port);
        let (port, server) = start_proxy(stats.clone(), false).await;

        let init = unambiguous_client_init(&stats.secret, 2);
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&init).await.unwrap();

        wait_until("сбой засчитан", || {
            stats.ws_failures.load(Ordering::Relaxed) > 0
        })
        .await;

        let events = stats.drain_events();
        let named = events
            .iter()
            .find(|event| event.contains("Не поднялся туннель до DC2"))
            .unwrap_or_else(|| panic!("причина отказа не попала в журнал: {events:?}"));
        assert!(
            named.contains("127.0.0.1"),
            "в журнале должен быть назван адрес, до которого не дошли: {named}"
        );

        stats.stop();
        let _ = server.await.unwrap();
    }

    /// Строка, не похожая на имя хоста, отбрасывалась молча, и «воркер
    /// настроен» ничем не отличалось от «воркера нет» (by-sonic/tglock#50).
    #[test]
    fn a_worker_domain_is_confirmed_or_named_as_rejected() {
        let stats = Stats::new();
        stats.set_worker_domain("https://mine.workers.dev/, spare.workers.dev");
        let events = stats.drain_events();

        assert!(
            events
                .iter()
                .any(|event| event.contains("https://mine.workers.dev/")
                    && event.contains("не похож на имя хоста")),
            "отвергнутый домен должен быть назван вместе с причиной: {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|event| event.contains("в списке маршрутов: spare.workers.dev")),
            "принятый домен нужно подтвердить, иначе проверить нечем: {events:?}"
        );
    }

    /// Ping от той стороны обязан получить Pong, и туннель обязан это пережить.
    ///
    /// Ping приходит в читающую половину, а отвечать на него должна пишущая.
    /// Единственный маршрут, где Ping вообще бывает, — Cloudflare Worker:
    /// у Telegram его нет. Поэтому поломка на этом пути видна только тем, у
    /// кого настроен воркер (by-sonic/tglock#42).
    #[allow(clippy::result_large_err)]
    #[tokio::test]
    async fn a_ping_is_answered_and_the_tunnel_survives_it() {
        use futures_util::{SinkExt, StreamExt};

        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_port = relay_listener.local_addr().unwrap().port();
        let (report_tx, report_rx) = tokio::sync::oneshot::channel::<Result<Vec<u8>, String>>();

        tokio::spawn(async move {
            let (tcp, _) = relay_listener.accept().await.unwrap();
            let mut websocket =
                tokio_tungstenite::accept_hdr_async(tcp, |_: &Request, mut response: Response| {
                    response.headers_mut().insert(
                        "Sec-WebSocket-Protocol",
                        "binary".parse().expect("static header value"),
                    );
                    Ok(response)
                })
                .await
                .unwrap();

            let init = match websocket.next().await {
                Some(Ok(Message::Binary(data))) => data,
                other => {
                    let _ = report_tx.send(Err(format!("ожидался init, пришло {other:?}")));
                    return;
                }
            };
            let header: [u8; INIT_LEN] = init.as_slice().try_into().unwrap();
            let mut relay = crate::mtproto::test_relay_peer(&header);

            websocket
                .send(Message::Ping(b"keepalive".to_vec()))
                .await
                .unwrap();

            let mut answered = false;
            let mut payload = Vec::new();
            while payload.is_empty() {
                match websocket.next().await {
                    Some(Ok(Message::Pong(pong))) => {
                        answered = pong == b"keepalive";
                    }
                    Some(Ok(Message::Binary(mut data))) => {
                        relay.decrypt(&mut data);
                        payload.extend_from_slice(&data);
                    }
                    Some(Ok(_)) => {}
                    other => {
                        let _ = report_tx.send(Err(format!(
                            "туннель закрылся до полезных данных: {other:?}"
                        )));
                        return;
                    }
                }
            }
            let _ = report_tx.send(if answered {
                Ok(payload)
            } else {
                Err("Pong не пришёл".to_owned())
            });
        });

        let stats = Stats::new();
        stats.transport.force_local_route(relay_port);
        let (port, server) = start_proxy(stats.clone(), false).await;

        let init = unambiguous_client_init(&stats.secret, -4);
        let mut peer = crate::mtproto::test_client_peer(&init, &stats.secret);
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&init).await.unwrap();

        // Клиент шлёт после Ping'а: если ответ на Ping ломает пишущую половину,
        // это не дойдёт.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let request = b"a request sent after the ping".to_vec();
        let mut wire = request.clone();
        peer.encrypt(&mut wire);
        client.write_all(&wire).await.unwrap();

        let report = tokio::time::timeout(Duration::from_secs(5), report_rx)
            .await
            .expect("реле должно доложить о результате")
            .unwrap();
        assert_eq!(report, Ok(request), "Ping не должен ломать туннель");

        stats.stop();
        let _ = server.await.unwrap();
    }

    /// Клиент, открывший соединение и промолчавший, обязан быть посчитан.
    ///
    /// До этого он не попадал никуда: `не опознано` растёт только когда запрос
    /// пришёл и не разобрался. Репортёр #42 видел, что телефон переоткрывает
    /// соединение примерно раз в десять секунд — ровно период `IO_TIMEOUT`, —
    /// и проверить это по диагностике было нечем.
    #[tokio::test(start_paused = true)]
    async fn a_client_that_says_nothing_is_counted_and_named() {
        let stats = Stats::new();
        let (port, server) = start_proxy(stats.clone(), false).await;

        // Соединение открыто и молчит. Время в тесте идёт само, как только
        // рантайму больше нечего делать.
        let _client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

        // Бюджет ожидания должен быть больше `IO_TIMEOUT`: время в тесте
        // виртуальное и прыгает к ближайшему сроку, поэтому пятисекундный
        // предел `wait_until` сработал бы первым.
        tokio::time::timeout(Duration::from_secs(60), async {
            while stats.silent_clients.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("молчащий клиент должен быть посчитан");
        assert_eq!(
            stats.unknown_clients.load(Ordering::Relaxed),
            0,
            "молчание — не то же самое, что неразобранный запрос"
        );

        let events = stats.drain_events();
        assert!(
            events
                .iter()
                .any(|event| event.contains("не прислал ни байта")),
            "в журнале должно быть сказано, что клиент молчал: {events:?}"
        );

        stats.stop();
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires live Telegram network access"]
    async fn accepts_mtproto_and_builds_live_media_tunnel() {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);

        let stats = Stats::new();
        let server_stats = stats.clone();
        let server =
            tokio::spawn(async move { run(server_stats, ListenConfig::loopback(port)).await });
        while !stats.running.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }

        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let init = crate::mtproto::test_client_init(&stats.secret, -4);
        client.write_all(&init).await.unwrap();

        tokio::time::timeout(Duration::from_secs(10), async {
            while stats.last_route() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(stats.last_dc(), 4);
        assert_eq!(stats.ws_failures.load(Ordering::Relaxed), 0);

        stats.stop();
        server.await.unwrap().unwrap();
    }

    /// Скачивание не должно затыкать отправку.
    ///
    /// В `ws_tunnel` цикл `select!` помечен `biased`, то есть сначала всегда
    /// опрашивается ветка чтения из WebSocket. Пока Telegram присылает данные
    /// непрерывно — а именно так выглядит загрузка медиа или первичная
    /// синхронизация телефона — ветка чтения из клиента не опрашивается
    /// вообще, и исходящие пакеты клиента наверх не уходят.
    #[allow(clippy::result_large_err)]
    #[tokio::test]
    async fn a_download_in_flight_must_not_stop_the_client_from_sending() {
        use futures_util::{SinkExt, StreamExt};

        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_port = relay_listener.local_addr().unwrap().port();
        let uploads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let relay_uploads = uploads.clone();

        tokio::spawn(async move {
            let (tcp, _) = relay_listener.accept().await.unwrap();
            let websocket =
                tokio_tungstenite::accept_hdr_async(tcp, |_: &Request, mut response: Response| {
                    response.headers_mut().insert(
                        "Sec-WebSocket-Protocol",
                        "binary".parse().expect("static header value"),
                    );
                    Ok(response)
                })
                .await
                .unwrap();
            let (mut sink, mut stream) = websocket.split();

            match stream.next().await {
                Some(Ok(Message::Binary(_))) => {}
                other => panic!("expected an init frame, got {other:?}"),
            }

            tokio::spawn(async move {
                while let Some(message) = stream.next().await {
                    if let Ok(Message::Binary(data)) = message {
                        relay_uploads.fetch_add(data.len(), Ordering::Relaxed);
                    }
                }
            });

            // Непрерывный поток вниз — так выглядит загрузка медиа.
            while sink.send(Message::Binary(vec![0; 32 * 1024])).await.is_ok() {}
        });

        let stats = Stats::new();
        stats.transport.force_local_route(relay_port);
        let (port, server) = start_proxy(stats.clone(), false).await;

        let init = unambiguous_client_init(&stats.secret, -4);
        let client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (mut client_r, mut client_w) = client.into_split();
        client_w.write_all(&init).await.unwrap();

        // Клиент исправно читает загрузку, иначе он затыкал бы туннель сам.
        let downloaded = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = downloaded.clone();
        tokio::spawn(async move {
            let mut drain = vec![0; 64 * 1024];
            while let Ok(read) = client_r.read(&mut drain).await {
                if read == 0 {
                    break;
                }
                counted.fetch_add(read, Ordering::Relaxed);
            }
        });

        wait_until("загрузка пошла", || {
            downloaded.load(Ordering::Relaxed) > 1024 * 1024
        })
        .await;

        // Telegram ждёт от клиента подтверждений и запросов. Без них сессия
        // встаёт: «Подключено», а сообщения висят с часиками.
        tokio::spawn(async move {
            while client_w.write_all(&[0x42; 128]).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });

        tokio::time::timeout(Duration::from_secs(5), async {
            while uploads.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("пока идёт загрузка, клиент должен доставить наверх хоть один байт");

        stats.stop();
        let _ = server.await.unwrap();
    }

    /// Медленный клиент не должен останавливать весь туннель.
    ///
    /// `ws_tunnel` читает и пишет в одной задаче: пока `tcp_w.write_all` ждёт,
    /// когда клиент разберёт присланное, ветка чтения из клиента не
    /// опрашивается, и наверх не уходит ничего. Телефон по Wi-Fi разбирает
    /// поток медленнее, чем десктоп на той же машине по loopback — отсюда
    /// асимметрия «на компьютере работает, на телефоне нет».
    #[allow(clippy::result_large_err)]
    #[tokio::test]
    async fn a_slow_client_must_not_freeze_its_own_uploads() {
        use futures_util::{SinkExt, StreamExt};

        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_port = relay_listener.local_addr().unwrap().port();
        let uploads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let relay_uploads = uploads.clone();

        tokio::spawn(async move {
            let (tcp, _) = relay_listener.accept().await.unwrap();
            let websocket =
                tokio_tungstenite::accept_hdr_async(tcp, |_: &Request, mut response: Response| {
                    response.headers_mut().insert(
                        "Sec-WebSocket-Protocol",
                        "binary".parse().expect("static header value"),
                    );
                    Ok(response)
                })
                .await
                .unwrap();
            let (mut sink, mut stream) = websocket.split();

            match stream.next().await {
                Some(Ok(Message::Binary(_))) => {}
                other => panic!("expected an init frame, got {other:?}"),
            }

            tokio::spawn(async move {
                while let Some(message) = stream.next().await {
                    if let Ok(Message::Binary(data)) = message {
                        relay_uploads.fetch_add(data.len(), Ordering::Relaxed);
                    }
                }
            });

            while sink.send(Message::Binary(vec![0; 32 * 1024])).await.is_ok() {}
        });

        let stats = Stats::new();
        stats.transport.force_local_route(relay_port);
        let (port, server) = start_proxy(stats.clone(), false).await;

        let init = unambiguous_client_init(&stats.secret, -4);
        let client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (client_r, mut client_w) = client.into_split();
        client_w.write_all(&init).await.unwrap();

        // Клиент занят и не разбирает входящий поток: его приёмное окно
        // закрывается, и запись в него встаёт.
        wait_until("туннель поднялся", || {
            stats.last_route() != 0
        })
        .await;
        tokio::time::sleep(Duration::from_secs(2)).await;

        tokio::spawn(async move {
            while client_w.write_all(&[0x42; 128]).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            while uploads.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;

        drop(client_r);
        stats.stop();
        let _ = server.await.unwrap();
        result.expect("клиент, который не успевает читать, всё равно должен отправлять");
    }
}
