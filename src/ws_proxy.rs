use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite;
use tungstenite::client::IntoClientRequest;

fn log_path() -> std::path::PathBuf {
    std::env::temp_dir().join("tglock.log")
}

/// Append a line to the log file (and also print to stderr for console visibility).
fn log(msg: &str) {
    use std::io::Write;
    let ts = chrono::Local::now().format("%H:%M:%S%.3f");
    let line = format!("[{}] {}\n", ts, msg);
    eprint!("{}", line);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log_path()) {
        let _ = f.write_all(line.as_bytes());
    }
}

macro_rules! tlog {
    ($($arg:tt)*) => { log(&format!($($arg)*)) };
}

pub struct ProxyStats {
    pub running: AtomicBool,
    pub active_conn: AtomicU32,
    pub total_conn: AtomicU32,
    pub ws_active: AtomicU32,
    pub verbose: AtomicBool,
}

impl ProxyStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            running: AtomicBool::new(false),
            active_conn: AtomicU32::new(0),
            total_conn: AtomicU32::new(0),
            ws_active: AtomicU32::new(0),
            verbose: AtomicBool::new(false),
        })
    }
}

pub async fn run_proxy(port: u16, stats: Arc<ProxyStats>) -> Result<(), String> {
    run_proxy_bind("127.0.0.1", port, stats).await
}

pub async fn run_proxy_bind(
    bind: &str,
    port: u16,
    stats: Arc<ProxyStats>,
) -> Result<(), String> {
    let addr = format!("{}:{}", bind, port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("Не удалось занять порт {}: {}", port, e))?;

    tlog!("SOCKS5 proxy listening on {} (direct WSS, log: {})", addr, log_path().display());
    stats.running.store(true, Ordering::SeqCst);

    loop {
        if !stats.running.load(Ordering::SeqCst) {
            break;
        }
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        let st = stats.clone();
                        let conn_id = st.total_conn.fetch_add(1, Ordering::Relaxed) + 1;
                        st.active_conn.fetch_add(1, Ordering::Relaxed);
                        let verbose = st.verbose.load(Ordering::Relaxed);
                        if verbose {
                            tlog!("#{} accept from {} (active: {})",
                                conn_id, peer, st.active_conn.load(Ordering::Relaxed));
                        }
                        tokio::spawn(async move {
                            if let Err(e) = handle_socks5(stream, &st, conn_id).await {
                                tlog!("#{} error: {}", conn_id, e);
                            }
                            let remaining = st.active_conn.fetch_sub(1, Ordering::Relaxed) - 1;
                            if st.verbose.load(Ordering::Relaxed) {
                                tlog!("#{} closed (active: {})", conn_id, remaining);
                            }
                        });
                    }
                    Err(e) => {
                        tlog!("accept error: {}", e);
                    }
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {}
        }
    }

    stats.running.store(false, Ordering::SeqCst);
    Ok(())
}

// ---------------------------------------------------------------------------
// DC extraction from obfuscated2 init packet (same method as tg-ws-proxy)
// ---------------------------------------------------------------------------

/// Known obfuscated2 protocol tags (bytes 56-59 after decryption)
const TAG_ABRIDGED: u32 = 0xefefefef;
const TAG_INTERMEDIATE: u32 = 0xeeeeeeee;
const TAG_PADDED_INTERMEDIATE: u32 = 0xdddddddd;

#[derive(Debug)]
enum InitResult {
    /// Valid obfuscated2 init with detected DC
    Obfuscated2 { dc: u8, tag: u32, raw_dc: i16 },
    /// Decrypted DC is out of range 1-5 but tag looks valid
    BadDc { tag: u32, raw_dc: i16 },
    /// Not an obfuscated2 init packet (unknown protocol tag)
    NotObfuscated2 { tag: u32, raw_dc: i16 },
}

fn analyze_init(init: &[u8; 64]) -> InitResult {
    use aes::Aes256;
    use cipher::{KeyIvInit, StreamCipher};
    type Aes256Ctr = ctr::Ctr128BE<Aes256>;

    let key = &init[8..40];
    let iv = &init[40..56];

    let mut dec = [0u8; 64];
    dec.copy_from_slice(init);

    let mut cipher = Aes256Ctr::new(key.into(), iv.into());
    cipher.apply_keystream(&mut dec);

    let tag = u32::from_le_bytes([dec[56], dec[57], dec[58], dec[59]]);
    // DC is stored as i16 at bytes 60-61 (not i32 at 60-63)
    let raw_dc = i16::from_le_bytes([dec[60], dec[61]]);
    let dc = raw_dc.unsigned_abs() as u8;

    let is_known_tag = tag == TAG_ABRIDGED || tag == TAG_INTERMEDIATE || tag == TAG_PADDED_INTERMEDIATE;

    if is_known_tag && (1..=5).contains(&dc) {
        InitResult::Obfuscated2 { dc, tag, raw_dc }
    } else if is_known_tag {
        InitResult::BadDc { tag, raw_dc }
    } else {
        InitResult::NotObfuscated2 { tag, raw_dc }
    }
}

/// Check if an IP belongs to a known Telegram subnet (CIDR-based).
fn is_telegram_ip(addr: &str) -> bool {
    let ip: Ipv4Addr = match addr.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let n = u32::from(ip);

    // Official Telegram IP ranges
    const RANGES: &[(u32, u32)] = &[
        (0x959A_A000, 0x959A_AFFF), // 149.154.160.0/20
        (0x5B6C_0400, 0x5B6C_07FF), // 91.108.4.0/22
        (0x5B6C_0800, 0x5B6C_0BFF), // 91.108.8.0/22
        (0x5B6C_0C00, 0x5B6C_0FFF), // 91.108.12.0/22
        (0x5B6C_1000, 0x5B6C_13FF), // 91.108.16.0/22
        (0x5B6C_1400, 0x5B6C_17FF), // 91.108.20.0/22
        (0x5B6C_3800, 0x5B6C_3BFF), // 91.108.56.0/22
        (0xB94C_9700, 0xB94C_97FF), // 185.76.151.0/24
    ];

    RANGES.iter().any(|&(lo, hi)| n >= lo && n <= hi)
}

/// Best-effort DC guess from IP (only used as fallback).
fn dc_from_ip(ip: Ipv4Addr) -> Option<u8> {
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
            4..=7 => 4,
            8..=11 => 3,
            12..=15 => 4,
            16..=19 => 2,
            20..=23 => 2,
            56..=59 => 5,
            _ => 2,
        }),
        (185, 76) if o[2] == 151 => Some(2),
        _ => None,
    }
}

/// Endpoint format used by the proven tg-ws-proxy project
fn ws_url(dc: u8) -> String {
    format!("wss://kws{}.web.telegram.org/apiws", dc)
}

/// Hardcoded DC IPs — same as tg-ws-proxy. Avoids DNS resolution entirely.
fn dc_ip(dc: u8) -> &'static str {
    match dc {
        1 => "149.154.175.50",
        2 => "149.154.167.220",
        3 => "149.154.174.100",
        4 => "149.154.167.220",
        5 => "91.108.56.190",
        _ => "149.154.167.220",
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 handler
// ---------------------------------------------------------------------------

async fn handle_socks5(
    mut stream: TcpStream,
    stats: &ProxyStats,
    conn_id: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    stream.set_nodelay(true)?;
    let verbose = stats.verbose.load(Ordering::Relaxed);

    // --- auth negotiation ---
    let mut buf = [0u8; 258];
    let n = stream.read(&mut buf).await?;
    if n < 2 || buf[0] != 0x05 {
        return Err(format!("Not SOCKS5 (ver=0x{:02x}, len={})", buf[0], n).into());
    }
    stream.write_all(&[0x05, 0x00]).await?;

    // --- CONNECT request ---
    let n = stream.read(&mut buf).await?;
    if n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
        stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err(format!("Bad CONNECT (ver=0x{:02x}, cmd=0x{:02x}, len={})", buf[0], buf[1], n).into());
    }

    let (dest_addr, dest_port) = parse_dest(&buf[3..n])?;
    let is_tg = is_telegram_ip(&dest_addr);

    // SOCKS5 success (we handle the connection ourselves)
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38])
        .await?;

    if is_tg {
        // Read the first 64 bytes — obfuscated2 init packet
        let mut init = [0u8; 64];
        stream.read_exact(&mut init).await?;

        let analysis = analyze_init(&init);
        let dc_from_ip_val = dest_addr.parse::<Ipv4Addr>().ok().and_then(dc_from_ip);

        match &analysis {
            InitResult::Obfuscated2 { dc, tag, raw_dc } => {
                let tag_name = match *tag {
                    TAG_ABRIDGED => "abridged",
                    TAG_INTERMEDIATE => "intermediate",
                    TAG_PADDED_INTERMEDIATE => "padded-intermediate",
                    _ => "unknown",
                };
                tlog!("#{} telegram {}:{} -> DC{} (init-packet, {}, raw_dc={}, ip_dc={:?})",
                    conn_id, dest_addr, dest_port, dc, tag_name, raw_dc, dc_from_ip_val);

                stats.ws_active.fetch_add(1, Ordering::Relaxed);
                let ws_result = relay_via_ws(stream, *dc, &init, conn_id, verbose).await;
                let remaining_ws = stats.ws_active.fetch_sub(1, Ordering::Relaxed) - 1;

                match &ws_result {
                    Ok(()) => tlog!("#{} DC{} done (ws active: {})", conn_id, dc, remaining_ws),
                    Err(e) => tlog!("#{} DC{} tunnel error: {} (ws active: {})", conn_id, dc, e, remaining_ws),
                }
                ws_result?;
            }
            InitResult::BadDc { tag, raw_dc } => {
                let dc = dc_from_ip_val.unwrap_or(2);
                tlog!("#{} telegram {}:{} -> DC{} (ip-range fallback, init raw_dc={} out of range, tag=0x{:08x})",
                    conn_id, dest_addr, dest_port, dc, raw_dc, tag);

                stats.ws_active.fetch_add(1, Ordering::Relaxed);
                let ws_result = relay_via_ws(stream, dc, &init, conn_id, verbose).await;
                let remaining_ws = stats.ws_active.fetch_sub(1, Ordering::Relaxed) - 1;

                match &ws_result {
                    Ok(()) => tlog!("#{} DC{} done (ws active: {})", conn_id, dc, remaining_ws),
                    Err(e) => tlog!("#{} DC{} tunnel error: {} (ws active: {})", conn_id, dc, e, remaining_ws),
                }
                ws_result?;
            }
            InitResult::NotObfuscated2 { tag, raw_dc } => {
                tlog!("#{} NOT obfuscated2 {}:{} (tag=0x{:08x}, raw_dc={}) -> direct TCP",
                    conn_id, dest_addr, dest_port, tag, raw_dc);

                let target = format!("{}:{}", dest_addr, dest_port);
                let remote = TcpStream::connect(&target).await
                    .map_err(|e| format!("direct TCP connect {}:{}: {}", dest_addr, dest_port, e))?;
                let _ = remote.set_nodelay(true);
                let (mut remote_rx, mut remote_tx) = tokio::io::split(remote);
                remote_tx.write_all(&init).await?;
                let (mut tcp_rx, mut tcp_tx) = tokio::io::split(stream);
                tokio::select! {
                    r = tokio::io::copy(&mut tcp_rx, &mut remote_tx) => {
                        if let Err(e) = r {
                            if verbose { tlog!("#{} tcp c->r: {}", conn_id, e); }
                        }
                    }
                    r = tokio::io::copy(&mut remote_rx, &mut tcp_tx) => {
                        if let Err(e) = r {
                            if verbose { tlog!("#{} tcp r->c: {}", conn_id, e); }
                        }
                    }
                }
            }
        }
    } else {
        // Non-Telegram — direct TCP passthrough
        let target = format!("{}:{}", dest_addr, dest_port);
        if verbose {
            tlog!("#{} tcp passthrough to {}", conn_id, target);
        }
        match TcpStream::connect(&target).await {
            Ok(remote) => {
                let _ = remote.set_nodelay(true);
                relay_tcp(stream, remote).await;
            }
            Err(e) => return Err(format!("TCP connect {}: {}", target, e).into()),
        }
    }

    Ok(())
}

fn parse_dest(data: &[u8]) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>> {
    match data[0] {
        0x01 => {
            if data.len() < 7 { return Err("short".into()); }
            let ip = format!("{}.{}.{}.{}", data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((ip, port))
        }
        0x03 => {
            let len = data[1] as usize;
            if data.len() < 2 + len + 2 { return Err("short".into()); }
            let domain = std::str::from_utf8(&data[2..2 + len])?.to_string();
            let port = u16::from_be_bytes([data[2 + len], data[3 + len]]);
            Ok((domain, port))
        }
        0x04 => {
            if data.len() < 19 { return Err("short".into()); }
            let port = u16::from_be_bytes([data[17], data[18]]);
            let mut segs = [0u16; 8];
            for i in 0..8 {
                segs[i] = u16::from_be_bytes([data[1 + i * 2], data[2 + i * 2]]);
            }
            let ip = std::net::Ipv6Addr::new(
                segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7],
            );
            Ok((ip.to_string(), port))
        }
        _ => Err("unknown addr type".into()),
    }
}

// ---------------------------------------------------------------------------
// WebSocket tunnel — direct connection using hardcoded DC IPs
// ---------------------------------------------------------------------------

async fn relay_via_ws(
    tcp_stream: TcpStream,
    dc: u8,
    init: &[u8; 64],
    conn_id: u32,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = ws_url(dc);
    let ws_host = format!("kws{}.web.telegram.org", dc);
    let ws_port = 443u16;
    let ip = dc_ip(dc);

    let mut request = url.as_str().into_client_request()?;
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", "binary".parse()?);

    if verbose {
        tlog!("#{} ws connecting to {} ({}:{})...", conn_id, url, ip, ws_port);
    }

    // Direct connection using hardcoded DC IP (no DNS needed).
    // Same approach as tg-ws-proxy: connect to DC IP, TLS with SNI, no cert verify.
    let connect_fut = async {
        let tcp = TcpStream::connect(format!("{}:{}", ip, ws_port)).await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("TCP {}:{}: {}", ip, ws_port, e).into()
            })?;
        tcp.set_nodelay(true)?;

        // Disable cert verification — matches tg-ws-proxy behavior.
        // The DC IP may not match the cert's SAN.
        let tls = tokio_native_tls::TlsConnector::from(
            native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
                .build()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { format!("TLS: {}", e).into() })?
        );
        let tls_stream = tls.connect(&ws_host, tcp).await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("TLS to {} ({}): {}", ws_host, ip, e).into()
            })?;

        let (ws, resp) = tokio_tungstenite::client_async(request, tls_stream).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((ws, resp))
    };

    let (ws, resp) = match tokio::time::timeout(std::time::Duration::from_secs(10), connect_fut).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return Err(format!("WS connect to {} failed: {}", url, e).into()),
        Err(_) => return Err(format!("WS connect to {} timed out (10s)", url).into()),
    };

    tlog!("#{} ws connected {} (status: {})", conn_id, url, resp.status());
    ws_relay_loop(ws, tcp_stream, init, conn_id).await
}

async fn ws_relay_loop<S>(
    mut ws: tokio_tungstenite::WebSocketStream<S>,
    tcp_stream: TcpStream,
    init: &[u8; 64],
    conn_id: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures_util::{SinkExt, StreamExt};

    let (mut tcp_rx, mut tcp_tx) = tokio::io::split(tcp_stream);

    ws.send(tungstenite::Message::Binary(init.to_vec())).await
        .map_err(|e| format!("WS send init packet failed: {}", e))?;

    let mut buf = vec![0u8; 32768];
    let mut bytes_up: u64 = 64;
    let mut bytes_down: u64 = 0;
    let start = std::time::Instant::now();

    loop {
        tokio::select! {
            biased;

            ws_msg = ws.next() => {
                match ws_msg {
                    Some(Ok(tungstenite::Message::Binary(data))) => {
                        bytes_down += data.len() as u64;
                        if tcp_tx.write_all(data.as_ref()).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(tungstenite::Message::Ping(payload))) => {
                        if let Err(e) = ws.send(tungstenite::Message::Pong(payload)).await {
                            tlog!("#{} ws pong send failed: {}", conn_id, e);
                            break;
                        }
                    }
                    Some(Ok(tungstenite::Message::Close(frame))) => {
                        let reason = frame.as_ref()
                            .map(|f| format!("code={}, reason={}", f.code, f.reason))
                            .unwrap_or_else(|| "no reason".to_string());
                        tlog!("#{} ws server closed: {}", conn_id, reason);
                        break;
                    }
                    None => {
                        tlog!("#{} ws stream ended (server dropped)", conn_id);
                        break;
                    }
                    Some(Err(e)) => {
                        tlog!("#{} ws read error: {}", conn_id, e);
                        break;
                    }
                    _ => {}
                }
            }

            n = tcp_rx.read(&mut buf) => {
                match n {
                    Ok(0) => break,
                    Err(e) => {
                        tlog!("#{} ws TCP read error: {}", conn_id, e);
                        break;
                    }
                    Ok(n) => {
                        bytes_up += n as u64;
                        let msg = tungstenite::Message::Binary(buf[..n].to_vec());
                        if let Err(e) = ws.send(msg).await {
                            tlog!("#{} ws WS send failed: {}", conn_id, e);
                            break;
                        }
                    }
                }
            }
        }
    }

    let elapsed = start.elapsed();
    tlog!("#{} ws relay: up={} down={} duration={:.1}s",
        conn_id, fmt_bytes(bytes_up), fmt_bytes(bytes_down), elapsed.as_secs_f64());

    let _ = ws.close(None).await;
    Ok(())
}

fn fmt_bytes(b: u64) -> String {
    if b < 1024 { format!("{}B", b) }
    else if b < 1024 * 1024 { format!("{:.1}KB", b as f64 / 1024.0) }
    else { format!("{:.1}MB", b as f64 / (1024.0 * 1024.0)) }
}

async fn relay_tcp(client: TcpStream, remote: TcpStream) {
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut rr, mut rw) = tokio::io::split(remote);
    tokio::select! {
        _ = tokio::io::copy(&mut cr, &mut rw) => {}
        _ = tokio::io::copy(&mut rr, &mut cw) => {}
    }
}
