use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite;

pub const DEFAULT_PORT: u16 = 1080;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

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
    shutdown: Mutex<Option<tokio::sync::watch::Sender<bool>>>,
}

impl Stats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            running: AtomicBool::new(false),
            active: AtomicU32::new(0),
            total: AtomicU32::new(0),
            ws: AtomicU32::new(0),
            last_dc: AtomicU16::new(0),
            ws_failures: AtomicU32::new(0),
            last_route: AtomicU8::new(0),
            transport: crate::transport::TransportEngine::new(),
            secret: initial_secret(),
            shutdown: Mutex::new(None),
        })
    }

    pub fn telegram_secret(&self) -> String {
        crate::mtproto::telegram_secret(&self.secret)
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
fn initial_secret() -> [u8; 16] {
    crate::mtproto::load_or_create_secret()
}

#[cfg(test)]
fn initial_secret() -> [u8; 16] {
    crate::mtproto::generate_secret()
}

pub async fn run(stats: Arc<Stats>, lan: bool, port: u16) -> Result<(), String> {
    let host = if lan { "0.0.0.0" } else { "127.0.0.1" };
    let addr = format!("{}:{}", host, port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("Port {} busy: {}", port, e))?;

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
                            let _ = handle(stream, &s, !lan).await;
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

async fn handle(
    s: TcpStream,
    stats: &Stats,
    allow_direct: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut first = [0; 1];
    let peeked = tokio::time::timeout(IO_TIMEOUT, s.peek(&mut first))
        .await
        .map_err(|_| "client protocol detection timeout")??;
    if peeked == 0 {
        return Ok(());
    }
    if first[0] == 0x05 {
        handle_socks5(s, stats, allow_direct).await
    } else {
        handle_mtproto(s, stats).await
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
        stats.ws.fetch_add(1, Ordering::Relaxed);

        let r = ws_tunnel(s, dc, media, &init, None, stats).await;

        stats.ws.fetch_sub(1, Ordering::Relaxed);
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
    stats.ws.fetch_add(1, Ordering::Relaxed);
    let result = ws_tunnel(
        stream,
        parsed.dc,
        parsed.media,
        &parsed.relay_init,
        Some(parsed.crypto),
        stats,
    )
    .await;
    stats.ws.fetch_sub(1, Ordering::Relaxed);
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
        let server = tokio::spawn(async move { run(server_stats, false, port).await });

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
    #[ignore = "requires live Telegram network access"]
    async fn accepts_mtproto_and_builds_live_media_tunnel() {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);

        let stats = Stats::new();
        let server_stats = stats.clone();
        let server = tokio::spawn(async move { run(server_stats, false, port).await });
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
