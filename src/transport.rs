use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

// Живой адрес под нагрузкой не всегда укладывался в 4 с, а упавший маршрут уходит
// на паузу. Столько же ждёт Flowseal/tg-ws-proxy.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const FALLBACK_DELAY: Duration = Duration::from_millis(250);
const MAX_CONNECTING: usize = 3;
const FAILURE_BACKOFF_INITIAL: Duration = Duration::from_secs(30);
const FAILURE_BACKOFF_MAX: Duration = Duration::from_secs(30 * 60);
const HTTPS_PORT: u16 = 443;
const HTTP_PORT: u16 = 80;
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
    /// Свой домен на Cloudflare: записи `kwsN` указывают на адреса Telegram,
    /// и Cloudflare сам доводит WebSocket до дата-центра. Worker и его лимиты
    /// не нужны — так работает CF-прокси в Flowseal/tg-ws-proxy.
    CloudflareProxy,
    /// WebSocket без TLS на порту 80 родного адреса DC. Единственный прямой
    /// WebSocket к CDN203, у которого нет фронта на 443.
    TelegramPlainWs,
}

impl RouteKind {
    pub fn ui_code(self) -> u8 {
        match self {
            Self::TelegramIp => 1,
            Self::AlternateTelegramIp => 2,
            Self::SystemDns => 3,
            Self::CloudflareWorker => 4,
            Self::TelegramTcp => 5,
            Self::CloudflareProxy => 6,
            Self::TelegramPlainWs => 7,
        }
    }

    pub fn from_ui_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::TelegramIp),
            2 => Some(Self::AlternateTelegramIp),
            3 => Some(Self::SystemDns),
            4 => Some(Self::CloudflareWorker),
            5 => Some(Self::TelegramTcp),
            6 => Some(Self::CloudflareProxy),
            7 => Some(Self::TelegramPlainWs),
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
            Self::TelegramTcp => "Telegram TCP (MTProto)",
            Self::CloudflareProxy => "Cloudflare-прокси",
            Self::TelegramPlainWs => "Telegram WebSocket (порт 80)",
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
        Self::telegram_tcp(CDN203_IP)
    }

    /// Native obfuscated2 straight to a pinned Telegram address.
    fn telegram_tcp(ip: &str) -> Self {
        Self {
            connect_host: ip.to_owned(),
            websocket_host: String::new(),
            path: String::new(),
            kind: RouteKind::TelegramTcp,
            port: HTTPS_PORT,
            secure: false,
        }
    }

    /// WebSocket to a native Telegram address on port 80.
    ///
    /// There is no TLS here, but no less protection than on `telegram_tcp`: the
    /// payload is the same obfuscated MTProto stream, and MTProto authenticates
    /// the server itself. Here the address picks the DC and the Host header does
    /// not matter, so the address is all that goes in it.
    fn plain_ws(ip: &str) -> Self {
        Self {
            connect_host: ip.to_owned(),
            websocket_host: ip.to_owned(),
            path: "/apiws".to_owned(),
            kind: RouteKind::TelegramPlainWs,
            port: HTTP_PORT,
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
    cf_proxy_domains: Mutex<Vec<String>>,
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
        let result = split_domains(domains);
        *self.worker_domains.lock().unwrap() = result.accepted.clone();
        result
    }

    /// Задать свои домены на Cloudflare для CF-прокси (`kwsN.<домен>`).
    pub fn set_cf_proxy_domains(&self, domains: &[String]) -> WorkerDomains {
        let result = split_domains(domains);
        *self.cf_proxy_domains.lock().unwrap() = result.accepted.clone();
        result
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
        // Native TCP to an ordinary DC opens the moment the address is
        // reachable, long before Telegram answers, so racing it would beat
        // every slower working WebSocket. Like the TCP fallback in
        // Flowseal/tg-ws-proxy it is tried only once every other route failed.
        let (main, last_resort): (Vec<_>, Vec<_>) = self
            .ordered_candidates(key)
            .into_iter()
            .partition(|route| !is_last_resort(route));
        let mut errors = Vec::new();
        for candidates in [main, last_resort] {
            if let Some(winner) = self
                .race_candidates(key, candidates, &mut connect, &mut errors)
                .await
            {
                return Ok(winner);
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

    /// Race one tier of candidates; failures are appended to `errors`.
    async fn race_candidates<T, F, Fut>(
        &self,
        key: DcKey,
        candidates: Vec<Route>,
        connect: &mut F,
        errors: &mut Vec<String>,
    ) -> Option<(T, ConnectedRoute)>
    where
        F: FnMut(Route) -> Fut,
        Fut: std::future::Future<Output = Result<T, String>>,
    {
        let mut candidates = candidates.into_iter().peekable();
        let mut pending = FuturesUnordered::new();
        let mut next_start = Instant::now();

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
                            return Some((connection, ConnectedRoute { route }));
                        }
                        Err(error) => {
                            self.record_failure(&route);
                            let endpoint = match route.kind {
                                RouteKind::TelegramTcp => {
                                    format!("{}:{} (MTProto TCP)", route.connect_host, route.port)
                                }
                                RouteKind::TelegramPlainWs => {
                                    format!("{}:{} (WebSocket)", route.connect_host, route.port)
                                }
                                _ => format!(
                                    "{} (TLS {})",
                                    route.connect_host, route.websocket_host
                                ),
                            };
                            errors.push(format!("{endpoint} — {error}"));
                        }
                    }
                }
                _ = tokio::time::sleep_until(next_start),
                    if candidates.peek().is_some() && pending.len() < MAX_CONNECTING => {}
            }
        }
        None
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
                RouteKind::TelegramTcp if route.connect_host == CDN203_IP => 0,
                RouteKind::TelegramIp if Some(route) == all_routes.first() => 0,
                // The operator explicitly configured these independent paths.
                // Start them after the primary IP, before more potentially
                // blocked Telegram addresses consume the concurrency budget.
                RouteKind::CloudflareWorker | RouteKind::CloudflareProxy => 1,
                RouteKind::TelegramIp | RouteKind::AlternateTelegramIp => 2,
                RouteKind::SystemDns => 3,
                // Last resort, raced separately; see race_connections(). The
                // WebSocket goes first: its upgrade is an answer from Telegram,
                // while TCP only shows that the address accepts connections.
                RouteKind::TelegramPlainWs => 4,
                RouteKind::TelegramTcp => 5,
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
        for domain in self.cf_proxy_domains.lock().unwrap().iter() {
            let host = cf_proxy_host(key.dc, domain);
            routes.push(Route::https(
                host.clone(),
                host,
                "/apiws".to_owned(),
                RouteKind::CloudflareProxy,
            ));
        }
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

/// Host of a CF-proxy domain for a data centre: `kws<dc>.<domain>`, with DNS
/// records the operator points at the Telegram addresses (docs/CF_PROXY.md).
/// CDN203 keeps its own record; it must never be folded into DC2.
pub(crate) fn cf_proxy_host(dc: u16, domain: &str) -> String {
    format!("kws{}.{}", dc, domain)
}

/// Routes tried only once everything else failed: port 80, and native TCP to
/// an ordinary data centre. The CDN's native TCP is its primary route.
fn is_last_resort(route: &Route) -> bool {
    route.kind == RouteKind::TelegramPlainWs
        || (route.kind == RouteKind::TelegramTcp && route.connect_host != CDN203_IP)
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

/// Настоящий WebSocket-фронт Telegram: адрес и имена, которые он обслуживает.
struct WebFront {
    ip: &'static str,
    /// Основной кластер. Принимает и обычные соединения, и медиа.
    host: &'static str,
    /// Медиа-кластер (`-1`), только для медиа; см. `routes_for_dc`.
    media_host: &'static str,
}

const fn front(ip: &'static str, host: &'static str, media_host: &'static str) -> WebFront {
    WebFront {
        ip,
        host,
        media_host,
    }
}

/// Где Telegram принимает WebSocket. Первый фронт каждого DC — тот, на который
/// указывает `kwsN.web.telegram.org`.
///
/// Это не адреса из `telegram_ips`: те говорят только на родном MTProto и на
/// TLS не отвечают из любой сети. Фронт выбирает DC по имени хоста, а не по
/// заголовку клиента, так что имя и адрес здесь нельзя менять местами: `.220`
/// на `kws1` отвечает редиректом. Каждая пара проверена запросом `req_DH_params`:
/// сервер принимает только свой номер DC, поэтому за фронтом стоит именно он.
fn web_fronts(dc: u16) -> &'static [WebFront] {
    const DC1: &[WebFront] = &[
        front(
            "149.154.174.100",
            "kws1.web.telegram.org",
            "kws1-1.web.telegram.org",
        ),
        front(
            "149.154.174.200",
            "zws1.web.telegram.org",
            "zws1-1.web.telegram.org",
        ),
        front(
            "149.154.175.209",
            "pluto.web.telegram.org",
            "pluto-1.web.telegram.org",
        ),
    ];
    const DC2: &[WebFront] = &[
        front(
            "149.154.167.220",
            "kws2.web.telegram.org",
            "kws2-1.web.telegram.org",
        ),
        front(
            "149.154.167.99",
            "kws2.web.telegram.org",
            "kws2-1.web.telegram.org",
        ),
    ];
    const DC3: &[WebFront] = &[
        front(
            "149.154.174.100",
            "kws3.web.telegram.org",
            "kws3-1.web.telegram.org",
        ),
        front(
            "149.154.174.200",
            "zws3.web.telegram.org",
            "zws3-1.web.telegram.org",
        ),
        front(
            "149.154.175.209",
            "aurora.web.telegram.org",
            "aurora-1.web.telegram.org",
        ),
    ];
    const DC4: &[WebFront] = &[
        front(
            "149.154.167.220",
            "kws4.web.telegram.org",
            "kws4-1.web.telegram.org",
        ),
        front(
            "149.154.167.99",
            "kws4.web.telegram.org",
            "kws4-1.web.telegram.org",
        ),
    ];
    const DC5: &[WebFront] = &[
        front(
            "149.154.170.100",
            "kws5.web.telegram.org",
            "kws5-1.web.telegram.org",
        ),
        front(
            "149.154.170.200",
            "zws5.web.telegram.org",
            "zws5-1.web.telegram.org",
        ),
        front(
            "149.154.170.96",
            "flora.web.telegram.org",
            "flora-1.web.telegram.org",
        ),
    ];
    match dc {
        1 => DC1,
        2 => DC2,
        3 => DC3,
        4 => DC4,
        5 => DC5,
        _ => &[],
    }
}

/// Родные адреса MTProto: сюда ходит прямой TCP и Worker. TLS здесь нет.
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
    if dc == 203 {
        // CDN203 has no WebSocket frontend of its own: its address speaks only
        // native obfuscated2 on 443, and kws2 on any frontend is plain DC2, where
        // a CDN session has neither its keys nor its data. Port 80 of the same
        // address does lead to the CDN. Worker and CF proxy routes are added on
        // top in routes_for_key.
        return vec![Route::cdn_tcp(), Route::plain_ws(CDN203_IP)];
    }
    let fronts = web_fronts(dc);
    if fronts.is_empty() {
        return Vec::new();
    }

    // Only media may use the `-1` hosts. That cluster rejects an ordinary
    // connection's key exchange with -444 (measured on kws2-1 and kws4-1), and
    // Telegram Desktop answers -444 by turning the proxy off as misconfigured.
    let clusters: &[fn(&WebFront) -> &'static str] = if media {
        &[|front| front.media_host, |front| front.host]
    } else {
        &[|front| front.host]
    };
    let mut routes = Vec::new();
    for host in clusters {
        for (index, front) in fronts.iter().enumerate() {
            routes.push(Route::https(
                front.ip.to_owned(),
                host(front).to_owned(),
                "/apiws".to_owned(),
                if index == 0 {
                    RouteKind::TelegramIp
                } else {
                    RouteKind::AlternateTelegramIp
                },
            ));
        }
        let name = host(&fronts[0]).to_owned();
        routes.push(Route::https(
            name.clone(),
            name,
            "/apiws".to_owned(),
            RouteKind::SystemDns,
        ));
    }
    // Where the frontends are out of reach, the DC's own address may still
    // work. Raced only after everything above failed (race_connections).
    routes.push(Route::plain_ws(telegram_ips(dc)[0]));
    routes.push(Route::telegram_tcp(telegram_ips(dc)[0]));
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
        return Err(
            "native MTProto TCP разрешён только до закреплённых адресов Telegram".to_owned(),
        );
    }
    if route.kind == RouteKind::TelegramPlainWs && !allowed_plain_ws_route(route) {
        return Err(
            "WebSocket без TLS разрешён только до закреплённых адресов Telegram".to_owned(),
        );
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
        // Raw TCP has already returned above. Besides local fixtures, plain
        // WebSocket is only allowed to pinned Telegram addresses, checked above.
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

fn allowed_plain_ws_route(route: &Route) -> bool {
    #[cfg(test)]
    if route.connect_host == "127.0.0.1" {
        return !route.secure;
    }
    worker_allowed_destinations().contains(&route.connect_host.as_str())
        && route.port == HTTP_PORT
        && route.websocket_host == route.connect_host
        && !route.secure
}

fn allowed_tcp_route(route: &Route) -> bool {
    #[cfg(test)]
    if route.connect_host == "127.0.0.1" && !route.secure {
        return true;
    }
    worker_allowed_destinations().contains(&route.connect_host.as_str())
        && route.port == HTTPS_PORT
        && route.websocket_host.is_empty()
        && route.path.is_empty()
        && !route.secure
}

/// Нормализовать список доменов, отделив непохожие на имя хоста.
fn split_domains(domains: &[String]) -> WorkerDomains {
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
    WorkerDomains { accepted, rejected }
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
        assert_eq!(routes[0].connect_host, "149.154.167.220");
    }

    #[test]
    fn only_media_may_reach_the_dash_one_cluster() {
        // That cluster answers an ordinary key exchange with -444, and Telegram
        // Desktop reacts by disabling the proxy as misconfigured.
        for dc in [1, 2, 3, 4, 5] {
            let dash_one = |route: &Route| route.websocket_host.contains("-1.");
            assert!(
                !routes_for_dc(dc, false).iter().any(dash_one),
                "DC{dc} ordinary connection on a media-only cluster"
            );
            let media = routes_for_dc(dc, true);
            assert!(dash_one(&media[0]), "DC{dc}: {:?}", media[0]);
            // The main cluster accepts media too, so it stays as a fallback.
            assert!(media
                .iter()
                .any(|route| route.websocket_host == format!("kws{dc}.web.telegram.org")));
        }
    }

    #[test]
    fn websocket_routes_only_dial_real_frontends() {
        // The native addresses speak MTProto and answer TLS with garbage from
        // any network, so a WebSocket route there can never connect.
        for dc in [1, 2, 3, 4, 5, 203] {
            for media in [false, true] {
                for route in routes_for_dc(dc, media) {
                    if matches!(
                        route.kind,
                        RouteKind::TelegramTcp | RouteKind::TelegramPlainWs | RouteKind::SystemDns
                    ) {
                        continue;
                    }
                    assert!(
                        web_fronts(dc)
                            .iter()
                            .any(|front| front.ip == route.connect_host),
                        "DC{dc}: {route:?}"
                    );
                    assert!(route.secure, "DC{dc}: {route:?}");
                    assert_ne!(route.connect_host, telegram_ips(dc)[0], "DC{dc}");
                }
            }
        }
    }

    #[test]
    fn frontends_are_only_dialled_under_a_name_they_serve() {
        // A frontend picks the DC from the Host header, not from the client's
        // init: kws2 is DC2 whatever the header says, and .220 redirects kws1.
        for (dc, name) in [
            (1, "kws1."),
            (2, "kws2."),
            (3, "kws3."),
            (4, "kws4."),
            (5, "kws5."),
        ] {
            let routes = routes_for_dc(dc, false);
            assert!(routes[0].websocket_host.starts_with(name), "{routes:?}");
            let front = &web_fronts(dc)[0];
            assert_eq!(routes[0].connect_host, front.ip);
        }
        assert!(routes_for_dc(1, false)
            .iter()
            .all(|route| route.connect_host != "149.154.167.220"));
    }

    #[test]
    fn dc203_prefers_native_tcp_and_never_changes_the_cdn_destination() {
        let routes = routes_for_dc(203, false);
        assert_eq!(routes[0].kind, RouteKind::TelegramTcp);
        assert!(routes[0].websocket_host.is_empty());
        assert!(!routes[0].secure);
        assert_eq!(routes[0].connect_host, "91.105.192.100");
        assert_eq!(routes[1], Route::plain_ws("91.105.192.100"));
        assert_eq!(routes.len(), 2, "CDN203 has no WebSocket frontend on 443");
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
    fn production_websockets_use_tls_and_native_tcp_only_reaches_pinned_telegram_ips() {
        let engine = TransportEngine::new();
        engine.set_worker_domains(&["fallback.workers.dev".to_owned()]);
        engine.set_cf_proxy_domains(&["example.com".to_owned()]);
        for dc in [1, 2, 3, 4, 5, 203] {
            for media in [false, true] {
                let routes = engine.routes_for_key(DcKey { dc, media });
                assert!(!routes.is_empty(), "DC{dc} must have at least one route");
                for route in routes {
                    match route.kind {
                        RouteKind::TelegramTcp => {
                            assert_eq!(route.port, 443, "{route:?}");
                            assert!(
                                telegram_ips(dc).contains(&route.connect_host.as_str()),
                                "{route:?}"
                            );
                            assert!(allowed_tcp_route(&route));
                        }
                        // The only route without TLS: pinned address, and no
                        // Telegram name on the wire.
                        RouteKind::TelegramPlainWs => {
                            assert_eq!(route.port, 80, "{route:?}");
                            assert_eq!(route.connect_host, telegram_ips(dc)[0]);
                            assert_eq!(route.websocket_host, route.connect_host);
                            assert!(allowed_plain_ws_route(&route));
                        }
                        _ => {
                            assert_eq!(route.port, 443, "{route:?}");
                            assert!(route.secure, "{route:?}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn native_tcp_to_an_ordinary_dc_is_a_last_resort_but_cdn203_leads() {
        let engine = TransportEngine::new();
        engine.set_cf_proxy_domains(&["example.com".to_owned()]);
        for dc in [1, 2, 3, 4, 5] {
            let ordered = engine.ordered_candidates(DcKey { dc, media: true });
            let first_fallback = ordered
                .iter()
                .position(is_last_resort)
                .expect("every DC has a last-resort route");
            assert_eq!(ordered[first_fallback].kind, RouteKind::TelegramPlainWs);
            assert_eq!(ordered[first_fallback + 1].kind, RouteKind::TelegramTcp);
            assert_eq!(ordered.len(), first_fallback + 2, "DC{dc}: {ordered:?}");
        }
        let cdn = engine.ordered_candidates(DcKey {
            dc: 203,
            media: true,
        });
        assert_eq!(cdn[0], Route::cdn_tcp());
        assert!(!is_last_resort(&cdn[0]));
        assert_eq!(cdn.last(), Some(&Route::plain_ws(CDN203_IP)));
    }

    #[tokio::test]
    async fn plain_websocket_refuses_anything_but_a_pinned_address() {
        for route in [
            Route::plain_ws("203.0.113.5"),
            Route {
                websocket_host: "kws2.web.telegram.org".to_owned(),
                ..Route::plain_ws("149.154.167.51")
            },
            Route {
                port: 8080,
                ..Route::plain_ws("149.154.167.51")
            },
        ] {
            let error = connect_route(&route).await.unwrap_err();
            assert!(error.contains("без TLS"), "{route:?}: {error}");
        }
    }

    #[tokio::test]
    async fn native_tcp_is_dialed_only_after_every_other_route_failed() {
        use std::sync::Mutex as StdMutex;
        let key = DcKey { dc: 2, media: true };

        // A slow but working WebSocket wins; TCP is never dialed.
        let engine = TransportEngine::new();
        let dialed = Arc::new(StdMutex::new(Vec::new()));
        let log = dialed.clone();
        let (_, connected) = engine
            .race_connections(key, move |route: Route| {
                log.lock().unwrap().push(route.kind);
                async move {
                    if route.kind == RouteKind::TelegramIp {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        Ok(())
                    } else if route.kind == RouteKind::TelegramTcp {
                        Ok(())
                    } else {
                        Err("blocked".to_owned())
                    }
                }
            })
            .await
            .unwrap();
        assert_eq!(connected.route.kind, RouteKind::TelegramIp);
        assert!(!dialed.lock().unwrap().contains(&RouteKind::TelegramTcp));

        // Every WebSocket fails: the pinned TCP route carries the tunnel.
        let engine = TransportEngine::new();
        let (_, connected) = engine
            .race_connections(key, |route: Route| async move {
                if route.kind == RouteKind::TelegramTcp {
                    Ok(())
                } else {
                    Err("blocked".to_owned())
                }
            })
            .await
            .unwrap();
        assert_eq!(connected.route.kind, RouteKind::TelegramTcp);
        assert!(telegram_ips(2).contains(&connected.route.connect_host.as_str()));
    }

    #[test]
    fn cf_proxy_domains_become_kws_routes_and_keep_cdn203_separate() {
        let engine = TransportEngine::new();
        let result = engine.set_cf_proxy_domains(&[
            " Example.COM ".to_owned(),
            "https://bad.example/".to_owned(),
        ]);
        assert_eq!(result.accepted, ["example.com"]);
        assert_eq!(result.rejected, ["https://bad.example/"]);
        for (dc, host) in [(2, "kws2.example.com"), (203, "kws203.example.com")] {
            let routes = engine.routes_for_key(DcKey { dc, media: true });
            let proxy = routes
                .iter()
                .find(|route| route.kind == RouteKind::CloudflareProxy)
                .expect("CF proxy route");
            assert_eq!(proxy.connect_host, host);
            assert_eq!(proxy.websocket_host, host);
            assert_eq!(proxy.path, "/apiws");
            assert!(proxy.secure);
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
            RouteKind::CloudflareProxy,
            RouteKind::TelegramPlainWs,
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
        assert!(
            error.contains("только до закреплённых адресов Telegram"),
            "{error}"
        );
        assert!(routes_for_dc(999, false).is_empty());
        for dc in [1, 2, 3, 4, 5] {
            assert!(routes_for_dc(dc, false)
                .iter()
                .filter(|route| route.kind == RouteKind::TelegramTcp)
                .all(|route| route.connect_host == telegram_ips(dc)[0]));
        }
    }

    #[tokio::test]
    #[ignore = "requires live Telegram network access"]
    async fn port_80_answers_on_every_native_address() {
        for dc in [1, 2, 3, 4, 5, 203] {
            let route = Route::plain_ws(telegram_ips(dc)[0]);
            match connect_route(&route).await {
                Ok(TelegramConnection::WebSocket(mut websocket)) => {
                    websocket.close(None).await.unwrap()
                }
                other => panic!("DC{dc}: {other:?}"),
            }
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
