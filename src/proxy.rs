use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite;
use tungstenite::client::IntoClientRequest;

pub const PORT: u16 = 1080;

pub struct Stats {
    pub running: AtomicBool,
    pub active: AtomicU32,
    pub total: AtomicU32,
    pub ws: AtomicU32,
    pub last_dc: AtomicU8,
}

impl Stats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            running: AtomicBool::new(false),
            active: AtomicU32::new(0),
            total: AtomicU32::new(0),
            ws: AtomicU32::new(0),
            last_dc: AtomicU8::new(0),
        })
    }
}

pub async fn run(stats: Arc<Stats>, lan: bool) -> Result<(), String> {
    let host = if lan { "0.0.0.0" } else { "127.0.0.1" };
    let addr = format!("{}:{}", host, PORT);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("Port {} busy: {}", PORT, e))?;

    stats.running.store(true, Ordering::SeqCst);

    loop {
        if !stats.running.load(Ordering::SeqCst) {
            break;
        }
        tokio::select! {
            Ok((stream, _)) = listener.accept() => {
                let s = stats.clone();
                s.active.fetch_add(1, Ordering::Relaxed);
                s.total.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let _ = handle(stream, &s).await;
                    s.active.fetch_sub(1, Ordering::Relaxed);
                });
            }
            _ = tokio::time::sleep(Duration::from_millis(150)) => {}
        }
    }

    stats.running.store(false, Ordering::SeqCst);
    Ok(())
}

// -- SOCKS5 -----------------------------------------------------------------

async fn handle(
    mut s: TcpStream,
    stats: &Stats,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    s.set_nodelay(true)?;

    let mut buf = [0u8; 258];
    let n = s.read(&mut buf).await?;
    if n < 2 || buf[0] != 0x05 {
        return Err("not socks5".into());
    }
    s.write_all(&[0x05, 0x00]).await?;

    let n = s.read(&mut buf).await?;
    if n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
        s.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err("bad connect".into());
    }

    let (addr, port) = parse_addr(&buf[3..n])?;
    let tg = addr.parse::<Ipv4Addr>().ok().and_then(dc_from_ip).is_some();

    // success reply
    s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38]).await?;

    if tg {
        // Read 64-byte obfuscated2 init → extract real DC
        let mut init = [0u8; 64];
        s.read_exact(&mut init).await?;

        let dc = dc_from_init(&init).unwrap_or_else(|| {
            addr.parse::<Ipv4Addr>().ok().and_then(dc_from_ip).unwrap_or(2)
        });

        stats.last_dc.store(dc, Ordering::Relaxed);
        stats.ws.fetch_add(1, Ordering::Relaxed);

        let r = ws_tunnel(s, dc, &init).await;

        stats.ws.fetch_sub(1, Ordering::Relaxed);
        r?;
    } else {
        let remote = TcpStream::connect(format!("{}:{}", addr, port)).await?;
        let _ = remote.set_nodelay(true);
        tcp_relay(s, remote).await;
    }
    Ok(())
}

fn parse_addr(d: &[u8]) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>> {
    match d[0] {
        0x01 if d.len() >= 7 => {
            Ok((format!("{}.{}.{}.{}", d[1], d[2], d[3], d[4]),
                u16::from_be_bytes([d[5], d[6]])))
        }
        0x03 => {
            let l = d[1] as usize;
            if d.len() < 2 + l + 2 { return Err("short".into()); }
            Ok((std::str::from_utf8(&d[2..2 + l])?.into(),
                u16::from_be_bytes([d[2 + l], d[3 + l]])))
        }
        0x04 if d.len() >= 19 => {
            let mut seg = [0u16; 8];
            for i in 0..8 { seg[i] = u16::from_be_bytes([d[1 + i * 2], d[2 + i * 2]]); }
            let ip = std::net::Ipv6Addr::new(seg[0],seg[1],seg[2],seg[3],seg[4],seg[5],seg[6],seg[7]);
            Ok((ip.to_string(), u16::from_be_bytes([d[17], d[18]])))
        }
        _ => Err("bad addr".into()),
    }
}

// -- DC detection -----------------------------------------------------------

fn dc_from_init(init: &[u8; 64]) -> Option<u8> {
    use aes::Aes256;
    use cipher::{KeyIvInit, StreamCipher};
    type Ctr = ctr::Ctr128BE<Aes256>;

    let mut dec = *init;
    let mut c = Ctr::new(init[8..40].into(), init[40..56].into());
    c.apply_keystream(&mut dec);

    let id = i32::from_le_bytes([dec[60], dec[61], dec[62], dec[63]]);
    let dc = id.unsigned_abs() as u8;
    (1..=5).contains(&dc).then_some(dc)
}

fn dc_from_ip(ip: Ipv4Addr) -> Option<u8> {
    let o = ip.octets();
    match (o[0], o[1]) {
        (149, 154) => Some(match o[2] { 160..=163 => 1, 164..=167 => 2, 168..=171 => 3, 172..=175 => 1, _ => 2 }),
        (91, 108)  => Some(match o[2] { 56..=59 => 5, 8..=11 => 3, 12..=15 => 4, _ => 2 }),
        (91, 105) | (185, 76) => Some(2),
        _ => None,
    }
}

fn ws_url(dc: u8) -> String {
    format!("wss://kws{}.web.telegram.org/apiws", dc)
}

// -- WebSocket tunnel -------------------------------------------------------

async fn ws_tunnel(
    tcp: TcpStream,
    dc: u8,
    init: &[u8; 64],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures_util::{SinkExt, StreamExt};

    let mut req = ws_url(dc).as_str().into_client_request()?;
    req.headers_mut().insert("Sec-WebSocket-Protocol", "binary".parse()?);

    let tls = native_tls::TlsConnector::new().map_err(|e| format!("tls: {}", e))?;
    let connector = tokio_tungstenite::Connector::NativeTls(tls);

    let (mut ws, _) = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_tungstenite::connect_async_tls_with_config(req, None, false, Some(connector)),
    )
    .await
    .map_err(|_| "WS connect timeout")?
    .map_err(|e| format!("WS: {}", e))?;

    let (mut tcp_r, mut tcp_w) = tokio::io::split(tcp);

    // Send buffered init as first frame
    ws.send(tungstenite::Message::Binary(init.to_vec())).await?;

    let mut buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            biased;

            msg = ws.next() => match msg {
                Some(Ok(tungstenite::Message::Binary(data))) => {
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
