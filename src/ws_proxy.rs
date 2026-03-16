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
}

impl ProxyStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            running: AtomicBool::new(false),
            active_conn: AtomicU32::new(0),
            total_conn: AtomicU32::new(0),
            ws_active: AtomicU32::new(0),
        })
    }
}

pub async fn run_proxy(port: u16, stats: Arc<ProxyStats>) -> Result<(), String> {
    let addr = format!("127.0.0.1:{}", port);
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

/// DC name mapping from official Telegram MTProto transport docs
fn dc_ws_url(dc: u8) -> String {
    let name = match dc {
        1 => "pluto",
        2 => "venus",
        3 => "aurora",
        4 => "vesta",
        5 => "flora",
        _ => "venus",
    };
    format!("wss://{}.web.telegram.org/apiws", name)
}

async fn handle_socks5(
    mut stream: TcpStream,
    stats: &ProxyStats,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    stream.set_nodelay(true)?;

    let mut buf = [0u8; 258];
    let n = stream.read(&mut buf).await?;
    if n < 2 || buf[0] != 0x05 {
        return Err("Not SOCKS5".into());
    }
    stream.write_all(&[0x05, 0x00]).await?;

    let n = stream.read(&mut buf).await?;
    if n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
        stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err("Bad CONNECT".into());
    }

    let (dest_addr, dest_port) = parse_dest(&buf[3..n])?;

    let dc = dest_addr
        .parse::<Ipv4Addr>()
        .ok()
        .and_then(telegram_dc);

    if let Some(dc_id) = dc {
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38])
            .await?;

        stats.ws_active.fetch_add(1, Ordering::Relaxed);
        let result = relay_via_ws(stream, dc_id).await;
        stats.ws_active.fetch_sub(1, Ordering::Relaxed);

        if let Err(e) = result {
            return Err(format!("WS tunnel DC{}: {}", dc_id, e).into());
        }
    } else {
        let target = format!("{}:{}", dest_addr, dest_port);
        match TcpStream::connect(&target).await {
            Ok(remote) => {
                let _ = remote.set_nodelay(true);
                stream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                relay_tcp(stream, remote).await;
            }
            Err(_) => {
                stream
                    .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
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

fn telegram_dc(ip: Ipv4Addr) -> Option<u8> {
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
        (91, 105) => Some(2),
        (185, 76) => Some(2),
        _ => None,
    }
}

async fn relay_via_ws(
    tcp_stream: TcpStream,
    dc_id: u8,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures_util::{SinkExt, StreamExt};

    let ws_url = dc_ws_url(dc_id);
    let mut request = ws_url.as_str().into_client_request()?;

    // Required by the Telegram WebSocket transport protocol
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        "binary".parse()?,
    );
    request.headers_mut().insert(
        "Origin",
        "https://web.telegram.org".parse()?,
    );

    let connector = tokio_tungstenite::Connector::NativeTls(
        native_tls::TlsConnector::new().map_err(|e| format!("TLS: {}", e))?,
    );

    let (ws, _resp) = tokio_tungstenite::connect_async_tls_with_config(
        request,
        None,
        false,
        Some(connector),
    )
    .await?;

    let (mut ws_tx, mut ws_rx) = ws.split();
    let (mut tcp_rx, mut tcp_tx) = tokio::io::split(tcp_stream);

    let up = async {
        let mut buf = vec![0u8; 32768];
        loop {
            match tcp_rx.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let msg = tungstenite::Message::Binary(buf[..n].to_vec());
                    if ws_tx.send(msg).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = ws_tx.close().await;
    };

    let down = async {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                tungstenite::Message::Binary(data) => {
                    if tcp_tx.write_all(&data).await.is_err() {
                        break;
                    }
                }
                tungstenite::Message::Close(_) => break,
                _ => {}
            }
        }
    };

    tokio::select! {
        _ = up => {}
        _ = down => {}
    }

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
