use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const FAILURE_BACKOFF_INITIAL: Duration = Duration::from_secs(30);
const FAILURE_BACKOFF_MAX: Duration = Duration::from_secs(30 * 60);

pub type TelegramWebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RouteKind {
    TelegramIp,
    AlternateTelegramIp,
    SystemDns,
    CloudflareWorker,
}

impl RouteKind {
    pub fn ui_code(self) -> u8 {
        match self {
            Self::TelegramIp => 1,
            Self::AlternateTelegramIp => 2,
            Self::SystemDns => 3,
            Self::CloudflareWorker => 4,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Route {
    pub connect_host: String,
    pub websocket_host: String,
    pub path: String,
    pub kind: RouteKind,
}

#[derive(Clone, Debug)]
pub struct ConnectedRoute {
    pub route: Route,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct DcKey {
    dc: u16,
    media: bool,
}

#[derive(Clone, Copy, Debug)]
struct RouteHealth {
    failures: u32,
    retry_at: Instant,
}

#[derive(Default)]
struct HealthState {
    routes: HashMap<Route, RouteHealth>,
    preferred: HashMap<DcKey, Route>,
}

#[derive(Default)]
pub struct TransportEngine {
    health: Mutex<HealthState>,
    worker_domains: Mutex<Vec<String>>,
}

impl TransportEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_worker_domains(&self, domains: &[String]) {
        let mut normalized = Vec::new();
        for domain in domains {
            let domain = domain.trim().to_ascii_lowercase();
            if valid_domain(&domain) && !normalized.contains(&domain) {
                normalized.push(domain);
            }
        }
        *self.worker_domains.lock().unwrap() = normalized;
    }

    pub async fn connect(
        &self,
        dc: u16,
        media: bool,
    ) -> Result<(TelegramWebSocket, ConnectedRoute), String> {
        let key = DcKey { dc, media };
        let candidates = self.ordered_candidates(key);
        let mut errors = Vec::new();

        for route in candidates {
            match connect_route(&route).await {
                Ok(websocket) => {
                    self.record_success(key, &route);
                    return Ok((websocket, ConnectedRoute { route }));
                }
                Err(error) => {
                    self.record_failure(&route);
                    errors.push(format!(
                        "{} via {}: {}",
                        route.websocket_host, route.connect_host, error
                    ));
                }
            }
        }

        Err(format!(
            "all Telegram routes for DC{}{} failed: {}",
            dc,
            if media { " media" } else { "" },
            errors.join("; ")
        ))
    }

    fn ordered_candidates(&self, key: DcKey) -> Vec<Route> {
        let now = Instant::now();
        let all_routes = self.routes_for_key(key);
        let health = self.health.lock().unwrap();
        let preferred = health.preferred.get(&key);
        let mut candidates: Vec<_> = all_routes
            .iter()
            .filter(|route| {
                health
                    .routes
                    .get(route)
                    .is_none_or(|route_health| route_health.retry_at <= now)
            })
            .cloned()
            .collect();

        candidates.sort_by_key(|route| {
            let preferred_rank = u8::from(preferred != Some(route));
            let kind_rank = match route.kind {
                RouteKind::TelegramIp => 0,
                RouteKind::AlternateTelegramIp => 1,
                RouteKind::SystemDns => 2,
                RouteKind::CloudflareWorker => 3,
            };
            (preferred_rank, kind_rank)
        });

        // If every route is cooling down, retry the one that becomes available first.
        if candidates.is_empty() {
            if let Some((route, _)) = health
                .routes
                .iter()
                .filter(|(route, _)| all_routes.contains(route))
                .min_by_key(|(_, route_health)| route_health.retry_at)
            {
                candidates.push(route.clone());
            }
        }
        candidates
    }

    fn routes_for_key(&self, key: DcKey) -> Vec<Route> {
        let mut routes = routes_for_dc(key.dc, key.media);
        let Some(destination) = telegram_ips(key.dc).first() else {
            return routes;
        };
        for domain in self.worker_domains.lock().unwrap().iter() {
            routes.push(Route {
                connect_host: domain.clone(),
                websocket_host: domain.clone(),
                path: format!("/apiws?dst={}&dc={}", destination, key.dc),
                kind: RouteKind::CloudflareWorker,
            });
        }
        routes
    }

    fn record_success(&self, key: DcKey, route: &Route) {
        let mut health = self.health.lock().unwrap();
        health.routes.remove(route);
        health.preferred.insert(key, route.clone());
    }

    fn record_failure(&self, route: &Route) {
        let mut health = self.health.lock().unwrap();
        let failures = health
            .routes
            .get(route)
            .map_or(1, |route_health| route_health.failures.saturating_add(1));
        let exponent = failures.saturating_sub(1).min(6);
        let delay = FAILURE_BACKOFF_INITIAL
            .saturating_mul(2_u32.pow(exponent))
            .min(FAILURE_BACKOFF_MAX);
        health.routes.insert(
            route.clone(),
            RouteHealth {
                failures,
                retry_at: Instant::now() + delay,
            },
        );
    }
}

fn canonical_dc(dc: u16) -> u16 {
    if dc == 203 {
        2
    } else {
        dc
    }
}

fn telegram_ips(dc: u16) -> &'static [&'static str] {
    match dc {
        1 => &["149.154.175.50"],
        2 => &["149.154.167.51", "149.154.167.220"],
        3 => &["149.154.175.100"],
        4 => &["149.154.167.91", "149.154.167.220"],
        5 => &["149.154.171.5"],
        203 => &["91.105.192.100"],
        _ => &[],
    }
}

pub fn routes_for_dc(dc: u16, media: bool) -> Vec<Route> {
    let websocket_dc = canonical_dc(dc);
    let primary = format!("kws{}.web.telegram.org", websocket_dc);
    let secondary = format!("kws{}-1.web.telegram.org", websocket_dc);
    let websocket_hosts = if media {
        [secondary, primary]
    } else {
        [primary, secondary]
    };
    let ips = telegram_ips(dc);
    let mut routes = Vec::new();

    for websocket_host in &websocket_hosts {
        for (index, ip) in ips.iter().enumerate() {
            routes.push(Route {
                connect_host: (*ip).to_owned(),
                websocket_host: websocket_host.clone(),
                path: "/apiws".to_owned(),
                kind: if index == 0 {
                    RouteKind::TelegramIp
                } else {
                    RouteKind::AlternateTelegramIp
                },
            });
        }
        routes.push(Route {
            connect_host: websocket_host.clone(),
            websocket_host: websocket_host.clone(),
            path: "/apiws".to_owned(),
            kind: RouteKind::SystemDns,
        });
    }
    routes
}

async fn connect_route(route: &Route) -> Result<TelegramWebSocket, String> {
    let tcp = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((route.connect_host.as_str(), 443)),
    )
    .await
    .map_err(|_| "TCP connect timeout".to_owned())?
    .map_err(|error| format!("TCP connect: {}", error))?;
    tcp.set_nodelay(true)
        .map_err(|error| format!("TCP_NODELAY: {}", error))?;

    let url = format!("wss://{}{}", route.websocket_host, route.path);
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|error| format!("WebSocket request: {}", error))?;
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        "binary"
            .parse()
            .map_err(|error| format!("WebSocket protocol header: {}", error))?,
    );

    // The URI host remains the real Telegram hostname even when the TCP socket
    // is opened to a pinned IP. Native TLS therefore validates Telegram's
    // certificate and sends the correct SNI.
    let tls = native_tls::TlsConnector::new().map_err(|error| format!("TLS setup: {}", error))?;
    let connector = tokio_tungstenite::Connector::NativeTls(tls);
    tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_tungstenite::client_async_tls_with_config(request, tcp, None, Some(connector)),
    )
    .await
    .map_err(|_| "TLS/WebSocket timeout".to_owned())?
    .map(|(websocket, _)| websocket)
    .map_err(|error| format!("TLS/WebSocket handshake: {}", error))
}

fn valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_prefers_dash_one_websocket_host() {
        let routes = routes_for_dc(2, true);
        assert_eq!(routes[0].websocket_host, "kws2-1.web.telegram.org");
        assert_eq!(routes[0].connect_host, "149.154.167.51");
    }

    #[test]
    fn dc203_uses_dc2_websocket_and_its_own_ip() {
        let routes = routes_for_dc(203, false);
        assert_eq!(routes[0].websocket_host, "kws2.web.telegram.org");
        assert_eq!(routes[0].connect_host, "91.105.192.100");
    }

    #[test]
    fn successful_route_becomes_preferred() {
        let engine = TransportEngine::new();
        let key = DcKey {
            dc: 2,
            media: false,
        };
        let preferred = routes_for_dc(2, false)[2].clone();
        engine.record_success(key, &preferred);
        assert_eq!(engine.ordered_candidates(key)[0], preferred);
    }

    #[test]
    fn failed_route_enters_cooldown() {
        let engine = TransportEngine::new();
        let key = DcKey {
            dc: 2,
            media: false,
        };
        let failed = routes_for_dc(2, false)[0].clone();
        engine.record_failure(&failed);
        assert!(!engine.ordered_candidates(key).contains(&failed));
    }

    #[test]
    fn worker_is_explicit_and_validated() {
        let engine = TransportEngine::new();
        engine.set_worker_domains(&[
            "Example.User.Workers.dev".to_owned(),
            "https://invalid.example/path".to_owned(),
        ]);
        let routes = engine.routes_for_key(DcKey { dc: 4, media: true });
        let worker = routes
            .iter()
            .find(|route| route.kind == RouteKind::CloudflareWorker)
            .unwrap();
        assert_eq!(worker.websocket_host, "example.user.workers.dev");
        assert_eq!(worker.path, "/apiws?dst=149.154.167.91&dc=4");
        assert_eq!(
            routes
                .iter()
                .filter(|route| route.kind == RouteKind::CloudflareWorker)
                .count(),
            1
        );
    }

    #[tokio::test]
    #[ignore = "requires live Telegram network access"]
    async fn connects_to_all_production_data_centers() {
        let engine = TransportEngine::new();
        for dc in [1, 2, 3, 4, 5, 203] {
            let (mut websocket, connected) = engine.connect(dc, false).await.unwrap();
            assert!(!connected.route.websocket_host.is_empty());
            websocket.close(None).await.unwrap();
        }
    }
}
