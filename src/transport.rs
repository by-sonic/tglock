use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const FAILURE_BACKOFF_INITIAL: Duration = Duration::from_secs(30);
const FAILURE_BACKOFF_MAX: Duration = Duration::from_secs(30 * 60);
const HTTPS_PORT: u16 = 443;

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

    pub fn from_ui_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::TelegramIp),
            2 => Some(Self::AlternateTelegramIp),
            3 => Some(Self::SystemDns),
            4 => Some(Self::CloudflareWorker),
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
    /// Wrap the connection in TLS. Always true outside tests.
    pub secure: bool,
}

impl Route {
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
                    let attempt = format!("{} — {}", route.connect_host, error);
                    if !errors.contains(&attempt) {
                        errors.push(attempt);
                    }
                }
            }
        }

        // Текст читает человек: он попадает в журнал событий, и по нему
        // отличают «провайдер режет закреплённые адреса» от «воркер отвечает
        // отказом». Раньше причина отказа не доходила никуда, и при
        // `туннелей 0` узнать, почему их ноль, было нечем (by-sonic/tglock#50).
        Err(format!(
            "Не поднялся туннель до DC{}{}: {}",
            dc,
            if media { " (медиа)" } else { "" },
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

    fn record_failure(&self, route: &Route) {
        self.route_failures.fetch_add(1, Ordering::Relaxed);
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
        routes.push(Route::https(
            websocket_host.clone(),
            websocket_host.clone(),
            "/apiws".to_owned(),
            RouteKind::SystemDns,
        ));
    }
    routes
}

async fn connect_route(route: &Route) -> Result<TelegramWebSocket, String> {
    let tcp = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((route.connect_host.as_str(), route.port)),
    )
    .await
    .map_err(|_| "не отвечает (таймаут TCP)".to_owned())?
    .map_err(|error| format!("соединение не открылось: {}", error))?;
    tcp.set_nodelay(true)
        .map_err(|error| format!("TCP_NODELAY: {}", error))?;

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
        // Only reachable from tests, which run a local WebSocket server without
        // a certificate. Production routes are always built by `Route::https`.
        return tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio_tungstenite::client_async(request, MaybeTlsStream::Plain(tcp)),
        )
        .await
        .map_err(|_| "таймаут WebSocket".to_owned())?
        .map(|(websocket, _)| websocket)
        .map_err(|error| format!("рукопожатие WebSocket: {}", error));
    }

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
    .map_err(|_| "таймаут TLS/WebSocket".to_owned())?
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

    #[test]
    fn every_production_route_is_tls_on_443() {
        let engine = TransportEngine::new();
        engine.set_worker_domains(&["fallback.workers.dev".to_owned()]);
        for dc in [1, 2, 3, 4, 5, 203] {
            for media in [false, true] {
                let routes = engine.routes_for_key(DcKey { dc, media });
                assert!(!routes.is_empty(), "DC{dc} must have at least one route");
                for route in routes {
                    assert_eq!(route.port, 443, "{route:?}");
                    assert!(route.secure, "{route:?}");
                }
            }
        }
    }

    #[test]
    fn every_data_center_offers_a_pinned_ip_and_a_dns_route() {
        for dc in [1, 2, 3, 4, 5, 203] {
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
    fn all_routes_cooling_down_still_yields_the_soonest_retry() {
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

        let candidates = engine.ordered_candidates(key);
        assert_eq!(
            candidates.len(),
            1,
            "a fully cooling table must offer exactly one retry, not give up"
        );
        assert_eq!(candidates[0], routes[0]);
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
    fn worker_is_the_last_resort() {
        let engine = TransportEngine::new();
        engine.set_worker_domains(&["fallback.workers.dev".to_owned()]);
        let key = DcKey {
            dc: 2,
            media: false,
        };
        let candidates = engine.ordered_candidates(key);
        assert_eq!(
            candidates.last().unwrap().kind,
            RouteKind::CloudflareWorker,
            "third-party infrastructure must never be tried before Telegram itself"
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
        ] {
            assert_ne!(route_label(0), kind.label());
        }
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
