use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const FALLBACK_DELAY: Duration = Duration::from_millis(250);
const MAX_CONNECTING: usize = 3;
const FAILURE_BACKOFF_INITIAL: Duration = Duration::from_secs(30);
const FAILURE_BACKOFF_MAX: Duration = Duration::from_secs(30 * 60);
const HTTPS_PORT: u16 = 443;
const CDN203_IP: &str = "91.105.192.100";

pub type TelegramWebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug)]
pub enum TelegramConnection {
    WebSocket(Box<TelegramWebSocket>),
    /// Native obfuscated2 transport, currently restricted to the CDN203 IP.
    Tcp(TcpStream),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RouteKind {
    TelegramIp,
    AlternateTelegramIp,
    SystemDns,
    CloudflareWorker,
    TelegramTcp,
}

impl RouteKind {
    pub fn ui_code(self) -> u8 {
        match self {
            Self::TelegramIp => 1,
            Self::AlternateTelegramIp => 2,
            Self::SystemDns => 3,
            Self::CloudflareWorker => 4,
            Self::TelegramTcp => 5,
        }
    }

    pub fn from_ui_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::TelegramIp),
            2 => Some(Self::AlternateTelegramIp),
            3 => Some(Self::SystemDns),
            4 => Some(Self::CloudflareWorker),
            5 => Some(Self::TelegramTcp),
            _ => None,
        }
    }

    /// Human-readable name of the route, shown by both frontends.
    pub fn label(self) -> &'static str {
        match self {
            Self::TelegramIp => "Telegram IP",
            Self::AlternateTelegramIp => "Запасной Telegram IP",
            Self::SystemDns => "Системный DNS",
            Self::CloudflareWorker => "Cloudflare Worker",
            Self::TelegramTcp => "Telegram CDN TCP",
        }
    }
}

/// Label for a route code as stored in `Stats::last_route`.
///
/// Code `0` means no tunnel has been established yet, which must never be
/// reported as a working route.
pub fn route_label(ui_code: u8) -> &'static str {
    RouteKind::from_ui_code(ui_code).map_or("Маршрут ещё не выбран", RouteKind::label)
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Route {
    pub connect_host: String,
    pub websocket_host: String,
    pub path: String,
    pub kind: RouteKind,
    /// TCP port to dial. Always 443 for Telegram and for Cloudflare Workers.
    pub port: u16,
    /// TLS for WebSocket routes; false for native obfuscated2 CDN TCP.
    pub secure: bool,
}

impl Route {
    fn cdn_tcp() -> Self {
        Self {
            connect_host: CDN203_IP.to_owned(),
            websocket_host: String::new(),
            path: String::new(),
            kind: RouteKind::TelegramTcp,
            port: HTTPS_PORT,
            secure: false,
        }
    }

    /// A production route: TLS on 443.
    fn https(connect_host: String, websocket_host: String, path: String, kind: RouteKind) -> Self {
        Self {
            connect_host,
            websocket_host,
            path,
            kind,
            port: HTTPS_PORT,
            secure: true,
        }
    }
}

/// Что случилось с доменами Worker'а, которые задал пользователь.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkerDomains {
    /// Домены, попавшие в список маршрутов.
    pub accepted: Vec<String>,
    /// Строки, не похожие на имя хоста, — маршрута из них не вышло.
    pub rejected: Vec<String>,
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
    /// Сколько раз отдельный маршрут не ответил.
    ///
    /// Считается отдельно от `Stats::ws_failures`, который растёт только когда
    /// упали ВСЕ маршруты. Из-за этого диагностика показывала «сбоев 0», пока
    /// закреплённый адрес был недоступен и каждое холодное соединение молча
    /// откатывалось на следующий маршрут, тратя на это до восьми секунд
    /// (by-sonic/tglock#32).
    route_failures: AtomicU32,
    #[cfg(test)]
    forced_routes: Mutex<Vec<Route>>,
}

#[cfg(test)]
impl TransportEngine {
    /// Point every data centre at a local plaintext WebSocket server so the
    /// whole tunnel can be exercised without reaching Telegram.
    pub(crate) fn force_local_route(&self, port: u16) {
        self.force_local_route_with(port, RouteKind::TelegramIp, "/apiws".to_owned());
    }

    pub(crate) fn force_local_route_with(&self, port: u16, kind: RouteKind, path: String) {
        *self.forced_routes.lock().unwrap() = vec![Route {
            connect_host: "127.0.0.1".to_owned(),
            websocket_host: format!("127.0.0.1:{}", port),
            path,
            kind,
            port,
            secure: false,
        }];
    }
}

impl TransportEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Задать домены Worker'ов, вернув принятые и отвергнутые по отдельности.
    ///
    /// Отвергнутые возвращаются, потому что раньше они отбрасывались молча:
    /// вписанный со схемой или слэшем `https://name.workers.dev/` не проходил
    /// проверку, маршрут не появлялся, и «воркер настроен» ничем не отличалось
    /// от «воркера нет» (by-sonic/tglock#50).
    pub fn set_worker_domains(&self, domains: &[String]) -> WorkerDomains {
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        for domain in domains {
            let trimmed = domain.trim();
            if trimmed.is_empty() {
                continue;
            }
            let normalized = trimmed.to_ascii_lowercase();
            if !valid_domain(&normalized) {
                rejected.push(trimmed.to_owned());
            } else if !accepted.contains(&normalized) {
                accepted.push(normalized);
            }
        }
        *self.worker_domains.lock().unwrap() = accepted.clone();
        WorkerDomains { accepted, rejected }
    }

    pub async fn connect(
        &self,
        dc: u16,
        media: bool,
    ) -> Result<(TelegramConnection, ConnectedRoute), String> {
        let key = DcKey { dc, media };
        self.race_connections(key, |route| async move { connect_route(&route).await })
            .await
    }

    // A slow first IP must not hold every other route hostage. At most three
    // handshakes run per client, staggered so a healthy preferred route wins
    // without opening needless fallback sockets. Dropping this future or
    // returning a winner cancels every losing connection attempt.
    async fn race_connections<T, F, Fut>(
        &self,
        key: DcKey,
        mut connect: F,
    ) -> Result<(T, ConnectedRoute), String>
    where
        F: FnMut(Route) -> Fut,
        Fut: std::future::Future<Output = Result<T, String>>,
    {
        let mut candidates = self.ordered_candidates(key).into_iter().peekable();
        let mut pending = FuturesUnordered::new();
        let mut next_start = Instant::now();
        let mut errors = Vec::new();

        while candidates.peek().is_some() || !pending.is_empty() {
            if candidates.peek().is_some()
                && pending.len() < MAX_CONNECTING
                && (pending.is_empty() || Instant::now() >= next_start)
            {
                let route = candidates.next().unwrap();
                // Another client may have failed this route since we took our
                // snapshot. Never knowingly bypass its current cooldown.
                if !self.route_available(&route) {
                    continue;
                }
                let connection = connect(route.clone());
                pending.push(async move { (route, connection.await) });
                next_start = Instant::now() + FALLBACK_DELAY;
                continue;
            }
            tokio::select! {
                Some((route, result)) = pending.next(), if !pending.is_empty() => {
                    match result {
                        Ok(connection) => {
                            self.record_success(key, &route);
                            return Ok((connection, ConnectedRoute { route }));
                        }
                        Err(error) => {
                            self.record_failure(&route);
                            let endpoint = if route.kind == RouteKind::TelegramTcp {
                                format!("{}:{} (MTProto TCP)", route.connect_host, route.port)
                            } else {
                                format!("{} (TLS {})", route.connect_host, route.websocket_host)
                            };
                            errors.push(format!("{endpoint} — {error}"));
                        }
                    }
                }
                _ = tokio::time::sleep_until(next_start),
                    if candidates.peek().is_some() && pending.len() < MAX_CONNECTING => {}
            }
        }

        if errors.is_empty() {
            let routes = self.routes_for_key(key);
            let health = self.health.lock().unwrap();
            let retry = routes
                .iter()
                .filter_map(|route| health.routes.get(route))
                .map(|entry| entry.retry_at.saturating_duration_since(Instant::now()))
                .min();
            errors.push(match retry {
                Some(delay) => format!(
                    "маршруты на паузе после ошибок; повтор через {} с",
                    delay
                        .as_secs()
                        .saturating_add(u64::from(delay.subsec_nanos() != 0))
                ),
                None => "для этого дата-центра нет маршрутов".to_owned(),
            });
        }
        Err(format!(
            "Не поднялся туннель до DC{}{}: {}",
            key.dc,
            if key.media { " (медиа)" } else { "" },
            errors.join("; ")
        ))
    }

    fn route_available(&self, route: &Route) -> bool {
        self.health
            .lock()
            .unwrap()
            .routes
            .get(route)
            .is_none_or(|health| health.retry_at <= Instant::now())
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
                RouteKind::TelegramTcp => 0,
                RouteKind::TelegramIp if Some(route) == all_routes.first() => 0,
                // The operator explicitly configured this independent path.
                // Start it after the primary IP, before more potentially
                // blocked Telegram addresses consume the concurrency budget.
                RouteKind::CloudflareWorker => 1,
                RouteKind::TelegramIp | RouteKind::AlternateTelegramIp => 2,
                RouteKind::SystemDns => 3,
            };
            (preferred_rank, kind_rank)
        });

        candidates
    }

    fn routes_for_key(&self, key: DcKey) -> Vec<Route> {
        #[cfg(test)]
        {
            let forced = self.forced_routes.lock().unwrap();
            if !forced.is_empty() {
                return forced.clone();
            }
        }

        let mut routes = routes_for_dc(key.dc, key.media);
        let Some(path) = worker_path(key.dc) else {
            return routes;
        };
        for domain in self.worker_domains.lock().unwrap().iter() {
            let path = path.clone();
            routes.push(Route::https(
                domain.clone(),
                domain.clone(),
                path,
                RouteKind::CloudflareWorker,
            ));
        }
        routes
    }

    fn record_success(&self, key: DcKey, route: &Route) {
        let mut health = self.health.lock().unwrap();
        health.routes.remove(route);
        health.preferred.insert(key, route.clone());
    }

    /// Сколько отдельных маршрутов не ответило за время работы.
    pub fn route_failures(&self) -> u32 {
        self.route_failures.load(Ordering::Relaxed)
    }

    /// A successful WebSocket upgrade is not proof that its upstream works.
    /// Call this for upstream failures after the handshake, never merely for
    /// a client disconnect or a canceled losing connection attempt.
    pub fn report_route_failure(&self, connected: &ConnectedRoute) {
        self.record_failure(&connected.route);
    }

    fn record_failure(&self, route: &Route) {
        self.route_failures.fetch_add(1, Ordering::Relaxed);
        let mut health = self.health.lock().unwrap();
        health.preferred.retain(|_, preferred| preferred != route);
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

/// Path a user's Cloudflare Worker must serve for the given data centre.
///
/// This is the contract documented in `docs/CLOUDFLARE_WORKER.md`; both the
/// route builder and the tests derive the path from here so the documentation
/// cannot drift away from what the client actually requests.
pub(crate) fn worker_path(dc: u16) -> Option<String> {
    let destination = telegram_ips(dc).first()?;
    Some(format!("/apiws?dst={}&dc={}", destination, dc))
}

/// Every address a Worker may be asked to reach, so a deployment can refuse
/// anything else instead of becoming an open TCP proxy.
pub fn worker_allowed_destinations() -> Vec<&'static str> {
    let mut all: Vec<_> = [1, 2, 3, 4, 5, 203]
        .into_iter()
        .flat_map(|dc| telegram_ips(dc).iter().copied())
        .collect();
    all.sort_unstable();
    all.dedup();
    all
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
        203 => &[CDN203_IP],
        _ => &[],
    }
}

pub fn routes_for_dc(dc: u16, media: bool) -> Vec<Route> {
    if telegram_ips(dc).is_empty() {
        return Vec::new();
    }
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
    if dc == 203 {
        // CDN203 speaks native obfuscated2 on this exact IP:443. A WebSocket
        // handshake on the same address can time out even while MTProto is
        // healthy. Keep the destination unchanged and use its native wire
        // transport; never redirect CDN authorization to ordinary DC2.
        routes.push(Route::cdn_tcp());
    }

    for websocket_host in &websocket_hosts {
        for (index, ip) in ips.iter().enumerate() {
            routes.push(Route::https(
                (*ip).to_owned(),
                websocket_host.clone(),
                "/apiws".to_owned(),
                if index == 0 {
                    RouteKind::TelegramIp
                } else {
                    RouteKind::AlternateTelegramIp
                },
            ));
        }
        // DC203 uses the DC2 hostname only for TLS/HTTP virtual hosting.
        // Resolving it would connect to DC2 itself and send CDN sessions to
        // the wrong data centre. Its fallback must retain the CDN address.
        if dc != 203 {
            routes.push(Route::https(
                websocket_host.clone(),
                websocket_host.clone(),
                "/apiws".to_owned(),
                RouteKind::SystemDns,
            ));
        }
    }
    routes
}

async fn connect_route(route: &Route) -> Result<TelegramConnection, String> {
    connect_route_with_config(route, tls_config()).await
}

fn client_config(roots: rustls::RootCertStore) -> Arc<rustls::ClientConfig> {
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            client_config(rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            ))
        })
        .clone()
}

async fn connect_route_with_config(
    route: &Route,
    config: Arc<rustls::ClientConfig>,
) -> Result<TelegramConnection, String> {
    // Native TCP is a narrowly scoped CDN route, not a general proxy escape
    // hatch. Reject malformed raw routes before dialing anything.
    if route.kind == RouteKind::TelegramTcp && !allowed_tcp_route(route) {
        return Err("native MTProto TCP разрешён только для закреплённого CDN203".to_owned());
    }
    let tcp = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((route.connect_host.as_str(), route.port)),
    )
    .await
    .map_err(|_| "не отвечает (таймаут TCP)".to_owned())?
    .map_err(|error| format!("соединение не открылось: {}", error))?;
    tcp.set_nodelay(true)
        .map_err(|error| format!("TCP_NODELAY: {}", error))?;

    if route.kind == RouteKind::TelegramTcp {
        return Ok(TelegramConnection::Tcp(tcp));
    }

    let scheme = if route.secure { "wss" } else { "ws" };
    let url = format!("{}://{}{}", scheme, route.websocket_host, route.path);
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

    if !route.secure {
        // Raw TCP has already returned above. Plain WebSocket is only used by
        // local fixtures; production WebSocket routes are always HTTPS.
        return tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio_tungstenite::client_async(request, MaybeTlsStream::Plain(tcp)),
        )
        .await
        .map_err(|_| "таймаут WebSocket".to_owned())?
        .map(|(websocket, _)| TelegramConnection::WebSocket(Box::new(websocket)))
        .map_err(|error| format!("рукопожатие WebSocket: {}", error));
    }

    // The URI host remains the real Telegram hostname even when the TCP socket
    // is opened to a pinned IP. rustls validates that hostname and certificate
    // against the bundled roots, and sends that hostname in SNI. The explicit
    // ring provider avoids process-global provider selection and its panics.
    let connector = tokio_tungstenite::Connector::Rustls(config);
    tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_tungstenite::client_async_tls_with_config(request, tcp, None, Some(connector)),
    )
    .await
    .map_err(|_| "таймаут TLS/WebSocket".to_owned())?
    .map(|(websocket, _)| TelegramConnection::WebSocket(Box::new(websocket)))
    .map_err(|error| format!("TLS/WebSocket handshake: {}", error))
}

fn allowed_tcp_route(route: &Route) -> bool {
    #[cfg(test)]
    if route.connect_host == "127.0.0.1" && !route.secure {
        return true;
    }
    route.connect_host == CDN203_IP
        && route.port == HTTPS_PORT
        && route.websocket_host.is_empty()
        && route.path.is_empty()
        && !route.secure
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
    fn dc203_prefers_native_tcp_and_never_changes_the_cdn_destination() {
        let routes = routes_for_dc(203, false);
        assert_eq!(routes[0].kind, RouteKind::TelegramTcp);
        assert!(routes[0].websocket_host.is_empty());
        assert!(!routes[0].secure);
        assert_eq!(routes[0].connect_host, "91.105.192.100");
        assert_eq!(routes[1].websocket_host, "kws2.web.telegram.org");
        assert!(routes
            .iter()
            .all(|route| route.connect_host == "91.105.192.100"));
        assert!(!routes
            .iter()
            .any(|route| route.kind == RouteKind::SystemDns));
        let engine = TransportEngine::new();
        engine.set_worker_domains(&["cdn.workers.dev".to_owned()]);
        let routes = engine.routes_for_key(DcKey {
            dc: 203,
            media: true,
        });
        let ordered = engine.ordered_candidates(DcKey {
            dc: 203,
            media: true,
        });
        assert_eq!(ordered[0].kind, RouteKind::TelegramTcp);
        assert_eq!(ordered[1].kind, RouteKind::CloudflareWorker);
        assert!(routes
            .iter()
            .filter(|route| route.kind == RouteKind::CloudflareWorker)
            .all(|route| route.path == "/apiws?dst=91.105.192.100&dc=203"));
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

    #[test]
    fn production_websockets_use_tls_and_native_tcp_is_restricted_to_cdn203() {
        let engine = TransportEngine::new();
        engine.set_worker_domains(&["fallback.workers.dev".to_owned()]);
        for dc in [1, 2, 3, 4, 5, 203] {
            for media in [false, true] {
                let routes = engine.routes_for_key(DcKey { dc, media });
                assert!(!routes.is_empty(), "DC{dc} must have at least one route");
                for route in routes {
                    assert_eq!(route.port, 443, "{route:?}");
                    if route.kind == RouteKind::TelegramTcp {
                        assert_eq!(dc, 203);
                        assert_eq!(route.connect_host, CDN203_IP);
                        assert!(allowed_tcp_route(&route));
                    } else {
                        assert!(route.secure, "{route:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn every_data_center_offers_a_pinned_ip_and_a_dns_route() {
        for dc in [1, 2, 3, 4, 5] {
            let routes = routes_for_dc(dc, false);
            assert!(
                routes
                    .iter()
                    .any(|route| route.kind == RouteKind::TelegramIp),
                "DC{dc} must keep a pinned-IP route so a poisoned DNS answer is survivable"
            );
            assert!(
                routes
                    .iter()
                    .any(|route| route.kind == RouteKind::SystemDns),
                "DC{dc} must keep a DNS route so a stale pinned IP is survivable"
            );
        }
    }

    #[test]
    fn backoff_grows_with_each_failure_and_stops_at_the_ceiling() {
        let engine = TransportEngine::new();
        let route = routes_for_dc(2, false)[0].clone();

        // 30s doubling per failure, flattening at the 30-minute ceiling.
        let expected_seconds = [30, 60, 120, 240, 480, 960, 1800, 1800, 1800, 1800];
        for (index, expected) in expected_seconds.iter().enumerate() {
            let attempt = u32::try_from(index).unwrap() + 1;
            let before = Instant::now();
            engine.record_failure(&route);

            let health = engine.health.lock().unwrap();
            let entry = health.routes.get(&route).unwrap();
            assert_eq!(entry.failures, attempt);
            assert_eq!(
                entry.retry_at.saturating_duration_since(before).as_secs(),
                *expected,
                "attempt {attempt} must wait {expected}s"
            );
        }
        assert_eq!(
            *expected_seconds.last().unwrap(),
            FAILURE_BACKOFF_MAX.as_secs(),
            "the schedule must flatten at the declared ceiling"
        );
    }

    #[test]
    fn success_clears_the_penalty_accumulated_by_failures() {
        let engine = TransportEngine::new();
        let key = DcKey {
            dc: 2,
            media: false,
        };
        let route = routes_for_dc(2, false)[0].clone();

        engine.record_failure(&route);
        engine.record_failure(&route);
        assert!(!engine.ordered_candidates(key).contains(&route));

        engine.record_success(key, &route);
        assert!(!engine.health.lock().unwrap().routes.contains_key(&route));
        assert_eq!(engine.ordered_candidates(key)[0], route);
    }

    #[test]
    fn all_routes_cooling_down_do_not_bypass_the_backoff() {
        let engine = TransportEngine::new();
        let key = DcKey {
            dc: 5,
            media: false,
        };
        let routes = routes_for_dc(5, false);

        // Fail the first route once and the rest twice, so the first one is the
        // one that becomes available again soonest.
        engine.record_failure(&routes[0]);
        for route in &routes[1..] {
            engine.record_failure(route);
            engine.record_failure(route);
        }

        assert!(engine.ordered_candidates(key).is_empty());
    }

    #[test]
    fn worker_domains_are_rejected_unless_they_are_plain_hostnames() {
        let engine = TransportEngine::new();
        let result = engine.set_worker_domains(&[
            "https://scheme.workers.dev".to_owned(),
            "with.a/path".to_owned(),
            "no-dot".to_owned(),
            "-leading.workers.dev".to_owned(),
            "trailing-.workers.dev".to_owned(),
            "under_score.workers.dev".to_owned(),
            "spaces here.dev".to_owned(),
            String::new(),
            "good.workers.dev".to_owned(),
        ]);

        let workers: Vec<_> = engine
            .routes_for_key(DcKey {
                dc: 2,
                media: false,
            })
            .into_iter()
            .filter(|route| route.kind == RouteKind::CloudflareWorker)
            .collect();
        assert_eq!(workers.len(), 1, "only the valid hostname may survive");
        assert_eq!(result.accepted, vec!["good.workers.dev".to_owned()]);
        assert!(
            result.rejected.contains(&"https://scheme.workers.dev".to_owned()),
            "отвергнутая строка обязана вернуться названной, иначе о ней некому              сообщить: {:?}",
            result.rejected
        );
        assert!(
            !result.rejected.iter().any(String::is_empty),
            "пустая строка — не то, о чём стоит предупреждать: {:?}",
            result.rejected
        );
        assert_eq!(workers[0].websocket_host, "good.workers.dev");
    }

    #[test]
    fn worker_domains_are_replaced_not_appended() {
        let engine = TransportEngine::new();
        let key = DcKey {
            dc: 2,
            media: false,
        };
        engine.set_worker_domains(&["first.workers.dev".to_owned()]);
        engine.set_worker_domains(&["second.workers.dev".to_owned()]);

        let workers: Vec<_> = engine
            .routes_for_key(key)
            .into_iter()
            .filter(|route| route.kind == RouteKind::CloudflareWorker)
            .collect();
        assert_eq!(workers.len(), 1);
        assert_eq!(workers[0].websocket_host, "second.workers.dev");
    }

    #[test]
    fn explicit_worker_is_tried_before_redundant_telegram_fallbacks() {
        let engine = TransportEngine::new();
        engine.set_worker_domains(&["fallback.workers.dev".to_owned()]);
        let key = DcKey {
            dc: 2,
            media: false,
        };
        let candidates = engine.ordered_candidates(key);
        assert_eq!(candidates[0].kind, RouteKind::TelegramIp);
        assert_eq!(candidates[1].kind, RouteKind::CloudflareWorker);
        let worker = candidates
            .iter()
            .position(|route| route.kind == RouteKind::CloudflareWorker)
            .unwrap();
        let dns = candidates
            .iter()
            .position(|route| route.kind == RouteKind::SystemDns)
            .unwrap();
        assert!(
            worker < dns,
            "an explicitly configured independent path must not wait for every blocked IP"
        );
    }

    #[test]
    fn every_route_failure_is_counted() {
        // Диагностика показывала «сбоев 0», пока закреплённый адрес был мёртв и
        // соединения молча откатывались на запасной. Счётчик маршрутов должен
        // видеть каждое такое падение.
        let engine = TransportEngine::new();
        let routes = routes_for_dc(2, false);
        assert_eq!(engine.route_failures(), 0);

        engine.record_failure(&routes[0]);
        assert_eq!(engine.route_failures(), 1);

        engine.record_failure(&routes[0]);
        engine.record_failure(&routes[1]);
        assert_eq!(
            engine.route_failures(),
            3,
            "считаются все падения, включая повторные по тому же маршруту"
        );

        // Успех не обнуляет историю: она нужна, чтобы понять, что маршруты
        // перебирались, даже когда в итоге всё соединилось.
        engine.record_success(
            DcKey {
                dc: 2,
                media: false,
            },
            &routes[1],
        );
        assert_eq!(engine.route_failures(), 3);
    }

    #[test]
    fn documented_worker_contract_matches_the_requested_path() {
        // docs/CLOUDFLARE_WORKER.md promises exactly this shape.
        assert_eq!(
            worker_path(2).unwrap(),
            "/apiws?dst=149.154.167.51&dc=2",
            "the documented contract must match what the client requests"
        );
        assert_eq!(
            worker_path(203).unwrap(),
            "/apiws?dst=91.105.192.100&dc=203"
        );
        assert_eq!(worker_path(42), None);
    }

    #[test]
    fn worker_allowlist_covers_every_address_a_route_can_ask_for() {
        let allowed = worker_allowed_destinations();
        for dc in [1, 2, 3, 4, 5, 203] {
            for ip in telegram_ips(dc) {
                assert!(
                    allowed.contains(ip),
                    "{ip} is reachable via a route but missing from the Worker allowlist"
                );
            }
        }
        assert_eq!(
            allowed.len(),
            7,
            "the allowlist in worker/tglock-worker.js must be updated alongside this"
        );
    }

    #[test]
    fn route_codes_and_labels_round_trip() {
        for kind in [
            RouteKind::TelegramIp,
            RouteKind::AlternateTelegramIp,
            RouteKind::SystemDns,
            RouteKind::CloudflareWorker,
            RouteKind::TelegramTcp,
        ] {
            assert_eq!(RouteKind::from_ui_code(kind.ui_code()), Some(kind));
            assert_eq!(route_label(kind.ui_code()), kind.label());
        }
    }

    #[test]
    fn code_zero_is_never_reported_as_a_working_route() {
        assert_eq!(RouteKind::from_ui_code(0), None);
        assert_eq!(RouteKind::from_ui_code(9), None);
        for kind in [
            RouteKind::TelegramIp,
            RouteKind::AlternateTelegramIp,
            RouteKind::SystemDns,
            RouteKind::CloudflareWorker,
            RouteKind::TelegramTcp,
        ] {
            assert_ne!(route_label(0), kind.label());
        }
    }

    fn local_routes(count: usize) -> Vec<Route> {
        (0..count)
            .map(|index| Route {
                connect_host: "127.0.0.1".to_owned(),
                websocket_host: "localhost".to_owned(),
                path: format!("/{index}"),
                kind: RouteKind::TelegramIp,
                port: 443,
                secure: false,
            })
            .collect()
    }

    struct ActiveAttempt(Arc<std::sync::atomic::AtomicUsize>);

    impl Drop for ActiveAttempt {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_hanging_first_route_does_not_delay_a_working_fallback() {
        let engine = TransportEngine::new();
        *engine.forced_routes.lock().unwrap() = local_routes(3);
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let started = Instant::now();
        let (_, winner) = engine
            .race_connections(
                DcKey {
                    dc: 2,
                    media: false,
                },
                |route| {
                    let active = active.clone();
                    async move {
                        active.fetch_add(1, Ordering::SeqCst);
                        let _active = ActiveAttempt(active);
                        if route.path == "/1" {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                            Ok(())
                        } else {
                            std::future::pending::<Result<(), String>>().await
                        }
                    }
                },
            )
            .await
            .unwrap();
        assert_eq!(winner.route.path, "/1");
        assert_eq!(started.elapsed(), FALLBACK_DELAY + Duration::from_millis(1));
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "losing attempts must be canceled"
        );
        assert_eq!(
            engine.route_failures(),
            0,
            "cancellation is not a route failure"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn connection_races_are_bounded_and_cooldown_prevents_redialing() {
        let engine = TransportEngine::new();
        *engine.forced_routes.lock().unwrap() = local_routes(8);
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let key = DcKey {
            dc: 2,
            media: false,
        };
        let error = engine
            .race_connections(key, |_| {
                let active = active.clone();
                let peak = peak.clone();
                async move {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(current, Ordering::SeqCst);
                    let _active = ActiveAttempt(active);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    Err::<(), _>("test handshake failure".to_owned())
                }
            })
            .await
            .unwrap_err();
        assert!(error.contains("test handshake failure"));
        assert_eq!(peak.load(Ordering::SeqCst), MAX_CONNECTING);
        assert_eq!(engine.route_failures(), 8);
        let error = engine
            .race_connections(key, |_| {
                panic!("a route in cooldown must never be dialed");
                #[allow(unreachable_code)]
                std::future::ready(Ok::<(), String>(()))
            })
            .await
            .unwrap_err();
        assert!(error.contains("повтор через"));
        assert_eq!(engine.route_failures(), 8);
        tokio::time::advance(FAILURE_BACKOFF_INITIAL).await;
        assert_eq!(engine.ordered_candidates(key).len(), 8);
    }

    #[test]
    fn an_upstream_failure_removes_preference_and_starts_cooldown() {
        let engine = TransportEngine::new();
        let key = DcKey {
            dc: 2,
            media: false,
        };
        let route = routes_for_dc(2, false)[0].clone();
        engine.record_success(key, &route);
        engine.report_route_failure(&ConnectedRoute {
            route: route.clone(),
        });
        assert!(!engine.ordered_candidates(key).contains(&route));
        assert!(!engine.health.lock().unwrap().preferred.contains_key(&key));
        assert_eq!(engine.route_failures(), 1);
    }

    #[tokio::test]
    async fn unsupported_dc_reports_missing_routes_without_dialing() {
        let error = TransportEngine::new()
            .connect(999, false)
            .await
            .unwrap_err();
        assert!(error.contains("нет маршрутов"));
    }

    async fn local_tls_route(
        hostname: &str,
    ) -> (
        Route,
        Arc<rustls::ClientConfig>,
        tokio::task::JoinHandle<Option<String>>,
    ) {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
        let cert = certificate.cert.der().clone();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
            let Ok(tls) = acceptor.accept(socket).await else {
                return None;
            };
            let name = tls.get_ref().1.server_name().map(str::to_owned);
            #[allow(clippy::result_large_err)]
            let negotiate = |_: &tokio_tungstenite::tungstenite::handshake::server::Request,
                             mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                response.headers_mut().insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
                Ok(response)
            };
            let _ = tokio_tungstenite::accept_hdr_async(tls, negotiate).await;
            name
        });
        (
            Route {
                connect_host: "127.0.0.1".to_owned(),
                websocket_host: hostname.to_owned(),
                path: "/apiws".to_owned(),
                kind: RouteKind::TelegramIp,
                port,
                secure: true,
            },
            client_config(roots),
            task,
        )
    }

    #[tokio::test]
    async fn pinned_ip_tls_uses_uri_hostname_for_sni_and_certificate_validation() {
        let (route, config, server) = local_tls_route("localhost").await;
        connect_route_with_config(&route, config).await.unwrap();
        assert_eq!(server.await.unwrap().as_deref(), Some("localhost"));
    }

    #[tokio::test]
    async fn tls_rejects_a_trusted_certificate_for_a_different_hostname() {
        let (route, config, server) = local_tls_route("wrong.example").await;
        let error = connect_route_with_config(&route, config).await.unwrap_err();
        assert!(error.contains("TLS/WebSocket handshake"), "{error}");
        assert!(server.await.unwrap().is_none());
    }

    #[tokio::test]
    async fn production_roots_reject_an_untrusted_certificate() {
        let (route, _, server) = local_tls_route("localhost").await;
        let error = connect_route(&route).await.unwrap_err();
        assert!(error.contains("TLS/WebSocket handshake"), "{error}");
        assert!(server.await.unwrap().is_none());
        assert!(
            Arc::ptr_eq(&tls_config(), &tls_config()),
            "reuse the TLS configuration"
        );
    }

    #[tokio::test]
    async fn native_tcp_connects_without_sending_a_tls_or_websocket_handshake() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let engine = TransportEngine::new();
        engine.force_local_route_with(
            listener.local_addr().unwrap().port(),
            RouteKind::TelegramTcp,
            String::new(),
        );
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4];
            socket.read_exact(&mut bytes).await.unwrap();
            assert_eq!(
                &bytes, b"init",
                "first bytes must be native transport bytes"
            );
            socket.write_all(b"pong").await.unwrap();
        });
        let (connection, connected) =
            tokio::time::timeout(Duration::from_secs(1), engine.connect(203, true))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(connected.route.kind, RouteKind::TelegramTcp);
        let TelegramConnection::Tcp(mut socket) = connection else {
            panic!("native CDN route must return a TCP stream");
        };
        assert!(socket.nodelay().unwrap());
        socket.write_all(b"init").await.unwrap();
        let mut reply = [0; 4];
        tokio::time::timeout(Duration::from_secs(1), socket.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn raw_tcp_failure_is_named_and_enters_cooldown() {
        let engine = TransportEngine::new();
        // Port zero cannot accept a TCP connection; no external traffic.
        engine.force_local_route_with(0, RouteKind::TelegramTcp, String::new());
        let error = engine.connect(203, false).await.unwrap_err();
        assert!(error.contains("MTProto TCP"), "{error}");
        assert!(
            !error.contains("TLS"),
            "native transport must not be called TLS"
        );
        assert_eq!(engine.route_failures(), 1);
        assert!(engine
            .ordered_candidates(DcKey {
                dc: 203,
                media: false
            })
            .is_empty());
    }

    #[tokio::test]
    async fn raw_tcp_guard_rejects_a_different_destination_before_dialing() {
        let mut route = Route::cdn_tcp();
        route.connect_host = "127.0.0.2".to_owned();
        let error = connect_route(&route).await.unwrap_err();
        assert!(error.contains("только для закреплённого CDN203"), "{error}");
        for dc in [1, 2, 3, 4, 5, 999] {
            assert!(routes_for_dc(dc, false)
                .iter()
                .all(|route| route.kind != RouteKind::TelegramTcp));
        }
    }

    #[tokio::test]
    #[ignore = "requires live Telegram network access"]
    async fn connects_to_all_production_data_centers() {
        let engine = TransportEngine::new();
        for dc in [1, 2, 3, 4, 5, 203] {
            let (connection, connected) = engine.connect(dc, false).await.unwrap();
            assert!(!connected.route.connect_host.is_empty());
            match connection {
                TelegramConnection::WebSocket(mut websocket) => {
                    websocket.close(None).await.unwrap()
                }
                TelegramConnection::Tcp(mut socket) => {
                    use tokio::io::AsyncWriteExt;
                    socket.shutdown().await.unwrap();
                }
            }
        }
    }
}
