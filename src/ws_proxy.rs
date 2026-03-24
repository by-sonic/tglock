use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite;
use tungstenite::client::IntoClientRequest;

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

pub async fn run_proxy_bind(bind: &str, port: u16, stats: Arc<ProxyStats>) -> Result<(), String> {
    let addr = format!("{}:{}", bind, port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("Не удалось занять порт {}: {}", port, e))?;

    stats.running.store(true, Ordering::SeqCst);

    loop {
        if !stats.running.load(Ordering::SeqCst) {
            break;
        }
        tokio::select! {
            result = listener.accept() => {
                if let Ok((stream, _)) = result {
                    let st = stats.clone();
                    st.active_conn.fetch_add(1, Ordering::Relaxed);
                    st.total_conn.fetch_add(1, Ordering::Relaxed);
                    tokio::spawn(async move {
                        let _ = handle_socks5(stream, &st).await;
                        st.active_conn.fetch_sub(1, Ordering::Relaxed);
                    });
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

fn extract_dc_from_init(init: &[u8; 64]) -> Option<u8> {
    use aes::Aes256;
    use cipher::{KeyIvInit, StreamCipher};
    type Aes256Ctr = ctr::Ctr128BE<Aes256>;

    let key = &init[8..40];
    let iv = &init[40..56];

    let mut dec = [0u8; 64];
    dec.copy_from_slice(init);

    let mut cipher = Aes256Ctr::new(key.into(), iv.into());
    cipher.apply_keystream(&mut dec);

    let dc_id = i32::from_le_bytes([dec[60], dec[61], dec[62], dec[63]]);
    let dc = dc_id.unsigned_abs() as u8;
    if (1..=5).contains(&dc) {
        Some(dc)
    } else {
        None
    }
}

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
            56..=59 => 5,
            8..=11 => 3,
            12..=15 => 4,
            _ => 2,
        }),
        (91, 105) | (185, 76) => Some(2),
        _ => None,
    }
}

fn is_telegram_ip(addr: &str) -> bool {
    addr.parse::<Ipv4Addr>()
        .ok()
        .and_then(dc_from_ip)
        .is_some()
}

/// Endpoint format used by the proven tg-ws-proxy project
fn ws_url(dc: u8) -> String {
    format!("wss://kws{}.web.telegram.org/apiws", dc)
}

// ---------------------------------------------------------------------------
// SOCKS5 handler
// ---------------------------------------------------------------------------

async fn handle_socks5(
    mut stream: TcpStream,
    stats: &ProxyStats,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    stream.set_nodelay(true)?;

    // --- auth negotiation ---
    let mut buf = [0u8; 258];
    let n = stream.read(&mut buf).await?;
    if n < 2 || buf[0] != 0x05 {
        return Err("Not SOCKS5".into());
    }
    stream.write_all(&[0x05, 0x00]).await?;

    // --- CONNECT request ---
    let n = stream.read(&mut buf).await?;
    if n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
        stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err("Bad CONNECT".into());
    }

    let (dest_addr, dest_port) = parse_dest(&buf[3..n])?;
    let is_tg = is_telegram_ip(&dest_addr);
    let verbose = stats.verbose.load(Ordering::Relaxed);
    // SOCKS5 success (we handle the connection ourselves)
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38])
        .await?;

    if is_tg {
        // Read the first 64 bytes — obfuscated2 init packet
        let mut init = [0u8; 64];
        stream.read_exact(&mut init).await?;

        // Extract DC from init packet (primary), fall back to IP-based
        let dc = extract_dc_from_init(&init).unwrap_or_else(|| {
            dest_addr
                .parse::<Ipv4Addr>()
                .ok()
                .and_then(dc_from_ip)
                .unwrap_or(2)
        });

        if verbose {
            eprintln!("[+] Telegram {}:{} -> WSS DC{}", dest_addr, dest_port, dc);
        }

        stats.ws_active.fetch_add(1, Ordering::Relaxed);

        // Try WebSocket tunnel; fall back to direct TCP on failure
        let ws_result = relay_via_ws(stream, dc, &init).await;

        stats.ws_active.fetch_sub(1, Ordering::Relaxed);

        if verbose {
            eprintln!("[-] Telegram DC{} отключён", dc);
        }

        if let Err(e) = ws_result {
            return Err(format!("DC{} tunnel: {}", dc, e).into());
        }
    } else {
        // Non-Telegram — direct TCP passthrough
        let target = format!("{}:{}", dest_addr, dest_port);
        if verbose {
            eprintln!("[+] TCP {}:{}", dest_addr, dest_port);
        }
        match TcpStream::connect(&target).await {
            Ok(remote) => {
                let _ = remote.set_nodelay(true);
                relay_tcp(stream, remote).await;
            }
            Err(e) => {
                return Err(format!("TCP connect {}: {}", target, e).into());
            }
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
// WebSocket tunnel — reads init first, then relays
// ---------------------------------------------------------------------------

async fn relay_via_ws(
    tcp_stream: TcpStream,
    dc: u8,
    init: &[u8; 64],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures_util::{SinkExt, StreamExt};

    let url = ws_url(dc);
    let mut request = url.as_str().into_client_request()?;

    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", "binary".parse()?);

    let connector = tokio_tungstenite::Connector::NativeTls(
        native_tls::TlsConnector::new().map_err(|e| format!("TLS: {}", e))?,
    );

    let (mut ws, _resp) = tokio_tungstenite::connect_async_tls_with_config(
        request, None, false, Some(connector),
    )
    .await?;

    let (mut tcp_rx, mut tcp_tx) = tokio::io::split(tcp_stream);

    // Send the buffered 64-byte init as the first WebSocket message
    ws.send(tungstenite::Message::Binary(init.to_vec())).await?;

    // Single loop: handles TCP→WS, WS→TCP, and Ping/Pong in one place.
    // This ensures Pong replies are sent immediately so the server
    // doesn't kill the connection after a timeout.
    let mut buf = vec![0u8; 32768];

    loop {
        tokio::select! {
            biased;

            ws_msg = ws.next() => {
                match ws_msg {
                    Some(Ok(tungstenite::Message::Binary(data))) => {
                        if tcp_tx.write_all(data.as_ref()).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(tungstenite::Message::Ping(payload))) => {
                        let _ = ws.send(tungstenite::Message::Pong(payload)).await;
                    }
                    Some(Ok(tungstenite::Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }

            n = tcp_rx.read(&mut buf) => {
                match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let msg = tungstenite::Message::Binary(buf[..n].to_vec());
                        if ws.send(msg).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }

    let _ = ws.close(None).await;
    Ok(())
}

async fn relay_tcp(client: TcpStream, remote: TcpStream) {
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut rr, mut rw) = tokio::io::split(remote);
    tokio::select! {
        _ = tokio::io::copy(&mut cr, &mut rw) => {}
        _ = tokio::io::copy(&mut rr, &mut cw) => {}
    }
}
