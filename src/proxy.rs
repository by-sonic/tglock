use crate::config::ListenConfig;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU8, Ordering};
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

pub struct Stats {
    pub running: AtomicBool,
    pub active: AtomicU32,
    pub total: AtomicU32,
    pub ws: AtomicU32,
    pub last_dc: AtomicU16,
    pub ws_failures: AtomicU32,
    /// See `transport::RouteKind::ui_code`.
    pub last_route: AtomicU8,
    transport: crate::transport::TransportEngine,
    secret: [u8; 16],
    /// Почему секрет не удалось сохранить, если не удалось.
    secret_write_error: Option<String>,
    shutdown: Mutex<Option<tokio::sync::watch::Sender<bool>>>,
}

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
            last_dc: AtomicU16::new(0),
            ws_failures: AtomicU32::new(0),
            last_route: AtomicU8::new(0),
            transport: crate::transport::TransportEngine::new(),
            secret,
            secret_write_error,
            shutdown: Mutex::new(None),
        })
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
        self.transport.set_worker_domains(&domains);
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
                    Ok((stream, _)) => {
                        let s = stats.clone();
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
    let peeked = tokio::time::timeout(IO_TIMEOUT, stream.peek(&mut probe[..1]))
        .await
        .map_err(|_| "client protocol detection timeout")??;
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

async fn handle_socks5(
    mut s: TcpStream,
    stats: &Stats,
    allow_direct: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    s.set_nodelay(true)?;

    let (addr, port) = tokio::time::timeout(IO_TIMEOUT, read_socks5_request(&mut s))
        .await
        .map_err(|_| "SOCKS5 handshake timeout")??;
    let tg = addr.parse::<Ipv4Addr>().ok().and_then(dc_from_ip).is_some();
    if !tg && !allow_direct {
        write_socks_reply(&mut s, 0x02).await?;
        return Err("LAN mode only permits Telegram destinations".into());
    }

    // success reply
    s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38])
        .await?;

    if tg {
        // Read 64-byte obfuscated2 init → extract real DC
        let mut init = [0u8; 64];
        s.read_exact(&mut init).await?;

        let (dc, media) = dc_from_init(&init).unwrap_or_else(|| {
            addr.parse::<Ipv4Addr>()
                .ok()
                .and_then(dc_from_ip)
                .map_or((2, false), |dc| (dc, false))
        });

        stats.last_dc.store(dc, Ordering::Relaxed);

        let r = ws_tunnel(s, dc, media, &init, None, stats).await;

        if r.is_err() {
            stats.ws_failures.fetch_add(1, Ordering::Relaxed);
        }
        r?;
    } else {
        let remote = tokio::time::timeout(IO_TIMEOUT, TcpStream::connect((addr.as_str(), port)))
            .await
            .map_err(|_| "direct connection timeout")??;
        let _ = remote.set_nodelay(true);
        tcp_relay(s, remote).await;
    }
    Ok(())
}

async fn handle_mtproto(
    mut stream: TcpStream,
    stats: &Stats,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    stream.set_nodelay(true)?;
    let mut init = [0; 64];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut init))
        .await
        .map_err(|_| "MTProto init timeout")??;
    let parsed = crate::mtproto::parse_client_init(&init, &stats.secret)
        .ok_or("invalid MTProto init or secret")?;

    stats.last_dc.store(parsed.dc, Ordering::Relaxed);
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

fn dc_from_ip(ip: Ipv4Addr) -> Option<u16> {
    let o = ip.octets();
    match (o[0], o[1]) {
        (149, 154) => Some(match o[2] {
            160..=163 => 1,
            164..=167 => 2,
            168..=171 => 3,
            172..=175 => 1,
            _ => 2,
        }),
        (91, 108) => Some(match o[2] {
            56..=59 => 5,
            8..=11 => 3,
            12..=15 => 4,
            _ => 2,
        }),
        (91, 105) if o[2] == 192 => Some(203),
        (91, 105) | (185, 76) => Some(2),
        _ => None,
    }
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
    mut crypto: Option<crate::mtproto::CryptoContext>,
    stats: &Stats,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures_util::{SinkExt, StreamExt};

    let (mut ws, connected) = stats.transport.connect(dc, media).await?;
    let _tunnel = EstablishedTunnel::new(stats);
    stats
        .last_route
        .store(connected.route.kind.ui_code(), Ordering::Relaxed);

    let (mut tcp_r, mut tcp_w) = tokio::io::split(tcp);

    // Send buffered init as first frame
    ws.send(tungstenite::Message::Binary(init.to_vec())).await?;

    let mut buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            biased;

            msg = ws.next() => match msg {
                Some(Ok(tungstenite::Message::Binary(mut data))) => {
                    if let Some(crypto) = &mut crypto {
                        crypto.telegram_to_client(data.as_mut());
                    }
                    tcp_w.write_all(data.as_ref()).await?;
                    tcp_w.flush().await?;
                }
                Some(Ok(tungstenite::Message::Ping(p))) => {
                    let _ = ws.send(tungstenite::Message::Pong(p)).await;
                }
                Some(Ok(tungstenite::Message::Close(_))) | None => break,
                Some(Err(_)) => break,
                _ => {}
            },

            n = tcp_r.read(&mut buf) => match n {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Some(crypto) = &mut crypto {
                        crypto.client_to_telegram(&mut buf[..n]);
                    }
                    ws.send(tungstenite::Message::Binary(buf[..n].to_vec())).await?;
                }
            },
        }
    }

    let _ = ws.close(None).await;
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

    #[test]
    fn maps_known_telegram_networks_to_dc() {
        assert_eq!(dc_from_ip("149.154.160.1".parse().unwrap()), Some(1));
        assert_eq!(dc_from_ip("149.154.167.255".parse().unwrap()), Some(2));
        assert_eq!(dc_from_ip("91.108.58.1".parse().unwrap()), Some(5));
        assert_eq!(dc_from_ip("1.1.1.1".parse().unwrap()), None);
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
            stats.last_dc.load(Ordering::Relaxed) == 2
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

        assert_eq!(stats.last_dc.load(Ordering::Relaxed), 4);
        assert_eq!(
            stats.last_route.load(Ordering::Relaxed),
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
            stats.last_route.load(Ordering::Relaxed),
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

        wait_until("the init to be parsed", || {
            stats.last_dc.load(Ordering::Relaxed) == 2
        })
        .await;
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(
            stats.ws.load(Ordering::Relaxed),
            0,
            "a handshake still in flight must not be reported as a working tunnel"
        );
        assert_eq!(
            stats.last_route.load(Ordering::Relaxed),
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
            stats.last_route.load(Ordering::Relaxed),
            0,
            "a route must not be reported as working when every attempt failed"
        );
        assert_eq!(stats.ws.load(Ordering::Relaxed), 0);

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
            while stats.last_route.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(stats.last_dc.load(Ordering::Relaxed), 4);
        assert_eq!(stats.ws_failures.load(Ordering::Relaxed), 0);

        stats.stop();
        server.await.unwrap().unwrap();
    }
}
