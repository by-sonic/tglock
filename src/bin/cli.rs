//! TGLock without a graphical interface.
//!
//! Built with `--no-default-features` this binary links neither Tauri nor a
//! system WebView, so it runs on servers, in containers and on machines with no
//! GPU or monitor — the cases that make the GUI fail to start at all
//! (by-sonic/tglock#10, by-sonic/tglock#17).

use clap::Parser;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tglock_lib::cli_settings as config;
use tglock_lib::{proxy, transport};

const STATUS_POLL: Duration = Duration::from_secs(1);

/// Напечатать строку, вернув `false`, если stdout больше не принимает данные.
///
/// `println!` при ошибке записи паникует, а у демона stdout исчезает штатно: его
/// пускают в `head`, закрывают терминал, перезапускают сборщик логов. Падать из
/// за этого туннель не должен — он продолжает работать молча.
fn say(text: &str) -> bool {
    if let Some(log) = LOG_FILE.get() {
        return log.lock().unwrap().write_line(text).is_ok();
    }
    let mut out = std::io::stdout().lock();
    writeln!(out, "{text}").and_then(|()| out.flush()).is_ok()
}

/// Журнал вместо stdout, если задан `--log-file`.
static LOG_FILE: OnceLock<Mutex<LogFile>> = OnceLock::new();

/// Файл журнала с ротацией.
///
/// На роутере stdout сервиса уходит в системный журнал, и TGLock забивал его
/// строками состояния (by-sonic/tglock#53). Заполненный файл переименовывается
/// в `<имя>.1`, поэтому на диске лежит не больше двух файлов: flash и память
/// роутера не резиновые.
struct LogFile {
    path: PathBuf,
    /// `None` только внутри ротации: Windows не переименует открытый файл.
    file: Option<File>,
    written: u64,
    limit: u64,
}

impl LogFile {
    fn open(path: PathBuf, limit: u64) -> std::io::Result<Self> {
        let file = open_log(&path)?;
        let written = file.metadata()?.len();
        Ok(Self {
            path,
            file: Some(file),
            written,
            limit,
        })
    }

    fn write_line(&mut self, text: &str) -> std::io::Result<()> {
        let line = format!("{} {text}\n", timestamp(now_seconds()));
        if self.written > 0 && self.written + line.len() as u64 > self.limit {
            self.rotate()?;
        }
        let file = self.file.as_mut().ok_or(std::io::ErrorKind::NotFound)?;
        file.write_all(line.as_bytes())?;
        file.flush()?;
        self.written += line.len() as u64;
        Ok(())
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        let mut backup = self.path.clone().into_os_string();
        backup.push(".1");
        self.file = None;
        let _ = std::fs::remove_file(&backup);
        std::fs::rename(&self.path, &backup)?;
        self.file = Some(open_log(&self.path)?);
        self.written = 0;
        Ok(())
    }
}

/// В журнал попадает ссылка `tg://proxy` с секретом: читать его может только
/// владелец.
fn open_log(path: &Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// `2026-10-31 09:30:00` в UTC. Перевод дней в дату — civil_from_days из
/// https://howardhinnant.github.io/date_algorithms.html
fn timestamp(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        (seconds / 3600) % 24,
        (seconds / 60) % 60,
        seconds % 60
    )
}

#[derive(Debug, Parser)]
#[command(
    name = "tglock-cli",
    version,
    about = "TGLock без графического интерфейса: локальный MTProto-прокси через WebSocket"
)]
struct Args {
    /// Файл настроек. Если не задан, ищется tglock.toml рядом с бинарём
    #[arg(short, long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Адрес для прослушивания. По умолчанию 127.0.0.1 — только этот компьютер
    #[arg(short, long, value_name = "IP")]
    bind: Option<IpAddr>,

    /// Порт локального прокси. По умолчанию 1080
    #[arg(short, long, value_name = "PORT")]
    port: Option<u16>,

    /// То же, что --bind 0.0.0.0: доступ с других устройств в локальной сети
    #[arg(long, conflicts_with = "bind")]
    lan: bool,

    /// Домен своего Cloudflare Worker как резервный маршрут. Можно повторять
    #[arg(long, value_name = "DOMAIN")]
    worker: Vec<String>,

    /// Свой домен на Cloudflare для CF-прокси (записи kws1…kws5, kws203 на
    /// адреса Telegram, docs/CF_PROXY.md). Можно повторять
    #[arg(long, value_name = "DOMAIN")]
    cf_proxy: Vec<String>,

    /// Проксировать и не-Telegram адреса. На сетевом адресе это открытый SOCKS5
    #[arg(long)]
    allow_direct: bool,

    /// Файл с секретом прокси. Для сервиса нужен он или secret в настройках:
    /// иначе после перезапуска секрет будет новым и настроенные клиенты отвалятся
    #[arg(long, value_name = "PATH")]
    secret_file: Option<PathBuf>,

    /// Печатать только ошибки
    #[arg(short, long)]
    quiet: bool,

    /// Писать журнал в этот файл, а не в stdout. Ошибки запуска всё равно идут
    /// в stderr. Заполненный файл переименовывается в <имя>.1
    #[arg(long, value_name = "PATH")]
    log_file: Option<PathBuf>,

    /// Размер файла журнала в МБ, после которого он сменяется. По умолчанию 5
    #[arg(long, value_name = "MB")]
    log_max_mb: Option<u32>,
}

impl Args {
    fn overrides(&self) -> config::Overrides {
        config::Overrides {
            bind: self.bind,
            port: self.port,
            lan: self.lan,
            allow_direct: self.allow_direct,
            worker: self.worker.clone(),
            cf_proxy: self.cf_proxy.clone(),
            secret_file: self.secret_file.clone(),
            quiet: self.quiet,
            log_file: self.log_file.clone(),
            log_max_mb: self.log_max_mb,
        }
    }

    /// Файл настроек и путь, по которому он найден.
    ///
    /// Явный `--config` обязателен к существованию: если человек указал путь и
    /// опечатался, молча стартовать с настройками по умолчанию — худшее из
    /// возможных поведений.
    fn load_file(&self) -> Result<(config::FileConfig, Option<PathBuf>), String> {
        if let Some(path) = &self.config {
            return Ok((config::FileConfig::load(path)?, Some(path.clone())));
        }
        match config::path_next_to_executable() {
            Some(path) if path.is_file() => Ok((config::FileConfig::load(&path)?, Some(path))),
            _ => Ok((config::FileConfig::default(), None)),
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("tglock-cli: не удалось запустить среду выполнения: {error}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(serve(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tglock-cli: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn serve(args: Args) -> Result<(), String> {
    let (file, file_path) = args.load_file()?;
    let settings = config::resolve(file, args.overrides())?;
    let listen = settings.listen;
    let stats = settings.stats();
    let quiet = settings.quiet;
    if let Some(path) = &settings.log_file {
        let log = LogFile::open(path.clone(), u64::from(settings.log_max_mb) * 1024 * 1024)
            .map_err(|error| format!("не удалось открыть журнал {}: {error}", path.display()))?;
        let _ = LOG_FILE.set(Mutex::new(log));
    }

    // Bind before printing anything: a busy port must be an error, not a
    // daemon that reports success and silently does nothing.
    let listener = proxy::bind(listen).await?;

    if !quiet {
        let intro = match &file_path {
            Some(path) => format!("Настройки: {}", path.display()),
            None => format!(
                "Настройки: только флаги ({} рядом с бинарём не найден)",
                config::DEFAULT_FILE_NAME
            ),
        };
        say(&intro);
        say(&format!("Слушаю {}", listen.addr));
        say(&format!(
            "Ссылка для Telegram: {}",
            listen.telegram_link(&stats.telegram_secret())
        ));
        // Запись секрета могла провалиться — тогда после перезапуска ссылка
        // изменится и Telegram скажет «прокси настроен неверно». Раньше это
        // происходило молча (by-sonic/tglock#37).
        if let Some(error) = stats.secret_write_error() {
            say(&format!(
                "Внимание: секрет НЕ сохранён ({error}). После перезапуска ссылка \
                 изменится, и Telegram откажется подключаться к старой"
            ));
        }
        if matches!(settings.secret, config::SecretSource::Ephemeral) {
            say(
                "Внимание: секрет не закреплён и будет новым после перезапуска — \
                 задайте secret в настройках или --secret-file",
            );
        }
        if listen.allow_direct && !listen.addr.ip().is_loopback() {
            say(&format!(
                "Внимание: allow_direct на адресе {} превращает TGLock в открытый SOCKS5-прокси",
                listen.addr.ip()
            ));
        } else if !listen.allow_direct {
            say("Пропускаю только адреса Telegram");
        }
        if !settings.workers.is_empty() {
            say(&format!("Резервные Worker-домены: {}", settings.workers));
        }
        if !settings.cf_proxies.is_empty() {
            say(&format!("CF-прокси домены: {}", settings.cf_proxies));
        }
    }

    let server_stats = stats.clone();
    let mut server =
        tokio::spawn(
            async move { proxy::serve(server_stats, listener, listen.allow_direct).await },
        );
    let watcher = (!quiet).then(|| tokio::spawn(watch_status(stats.clone())));

    let outcome = tokio::select! {
        joined = &mut server => joined.map_err(|error| format!("рабочая задача упала: {error}"))?,
        signal = shutdown_signal() => {
            signal.map_err(|error| format!("обработчик сигналов: {error}"))?;
            if !quiet {
                say("Получен сигнал остановки, закрываю соединения…");
            }
            stats.stop();
            server
                .await
                .map_err(|error| format!("рабочая задача упала: {error}"))?
        }
    };

    if let Some(watcher) = watcher {
        watcher.abort();
    }
    outcome
}

/// Print a line whenever the tunnel state changes.
///
/// This is the text equivalent of the GUI diagnostics tab: without it a daemon
/// gives journald nothing to show when Telegram stops working.
async fn watch_status(stats: Arc<proxy::Stats>) {
    let mut previous = None;
    loop {
        tokio::time::sleep(STATUS_POLL).await;

        // Отдельные события — кто подключился и какой адрес отклонён. Без них
        // journalctl показывает только счётчики, по которым нельзя отличить
        // «телефон не дошёл» от «дошёл и получил отказ» (by-sonic/tglock#42).
        for event in stats.drain_events() {
            if !say(&event) {
                return;
            }
        }

        let current = (
            stats.active.load(Ordering::Relaxed),
            stats.ws.load(Ordering::Relaxed),
            stats.last_dc(),
            stats.last_route(),
            stats.ws_failures.load(Ordering::Relaxed),
            stats.route_failures(),
            stats.blocked.load(Ordering::Relaxed),
            stats.unknown_clients.load(Ordering::Relaxed),
            stats.silent_clients.load(Ordering::Relaxed),
        );
        if previous.as_ref() == Some(&current) {
            continue;
        }
        let (active, tunnels, dc, route, failures, route_failures, blocked, unknown, silent) =
            current;
        let line = format!(
            "соединений {active} · туннелей {tunnels} · {} · {} · сбоев {failures} · \
             падений маршрутов {route_failures} · отклонено {blocked} · не опознано {unknown} ·              промолчали {silent}",
            if dc > 0 {
                format!("DC{dc}")
            } else {
                "DC не определён".to_owned()
            },
            transport::route_label(route)
        );
        // Закрытый stdout — не ошибка: печатать больше некому, туннель работает
        // дальше без наблюдателя.
        if !say(&line) {
            return;
        }
        previous = Some(current);
    }
}

/// Ctrl+C everywhere, plus SIGTERM on unix so `systemctl stop` shuts the
/// tunnel down cleanly instead of killing it.
#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Args {
        Args::try_parse_from(std::iter::once("tglock-cli").chain(args.iter().copied())).unwrap()
    }

    /// Итоговые настройки только из флагов, без файла.
    fn from_flags(args: &[&str]) -> config::Resolved {
        config::resolve(config::FileConfig::default(), parse(args).overrides()).unwrap()
    }

    /// Пустой каталог для одного теста, удаляется вместе с ним.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "tglock-cli-{name}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn log_rotation_keeps_the_newest_lines_in_two_bounded_files() {
        let dir = TempDir::new("rotation");
        let path = dir.0.join("tglock.log");
        let mut log = LogFile::open(path.clone(), 200).unwrap();
        for line in 0..40 {
            log.write_line(&format!("line {line}")).unwrap();
        }
        let current = std::fs::read_to_string(&path).unwrap();
        let backup = std::fs::read_to_string(dir.0.join("tglock.log.1")).unwrap();
        assert!(current.contains("line 39"), "{current}");
        assert!(current.len() <= 200 && backup.len() <= 200);
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 2);
    }

    #[test]
    fn a_restarted_daemon_continues_the_log_and_counts_what_is_there() {
        let dir = TempDir::new("restart");
        let path = dir.0.join("tglock.log");
        LogFile::open(path.clone(), 10_000)
            .unwrap()
            .write_line("first run")
            .unwrap();
        let mut log = LogFile::open(path.clone(), 10_000).unwrap();
        assert!(log.written > 0);
        log.write_line("second run").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("first run") && text.contains("second run"));
    }

    #[test]
    fn timestamps_are_calendar_dates_in_utc() {
        assert_eq!(timestamp(0), "1970-01-01 00:00:00");
        assert_eq!(timestamp(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(timestamp(1_793_442_645), "2026-10-31 10:30:45");
    }

    #[test]
    fn command_definition_is_valid() {
        Args::command().debug_assert();
    }

    #[test]
    fn defaults_to_loopback_on_the_default_port() {
        let listen = from_flags(&[]).listen;
        assert_eq!(listen.addr.to_string(), "127.0.0.1:1080");
        assert!(listen.allow_direct);
    }

    #[test]
    fn lan_flag_matches_explicit_wildcard_bind() {
        assert_eq!(
            from_flags(&["--lan"]).listen,
            from_flags(&["-b", "0.0.0.0"]).listen
        );
    }

    #[test]
    fn lan_does_not_relay_non_telegram_traffic() {
        let listen = from_flags(&["--lan"]).listen;
        assert_eq!(listen.addr.to_string(), "0.0.0.0:1080");
        assert!(!listen.allow_direct);
    }

    #[test]
    fn allow_direct_is_the_only_way_to_open_a_network_listener() {
        assert!(!from_flags(&["-b", "192.168.1.10"]).listen.allow_direct);
        assert!(
            from_flags(&["-b", "192.168.1.10", "--allow-direct"])
                .listen
                .allow_direct
        );
    }

    #[test]
    fn bind_and_port_are_honoured() {
        let listen = from_flags(&["--bind", "10.0.0.7", "--port", "1443"]).listen;
        assert_eq!(listen.addr.to_string(), "10.0.0.7:1443");
    }

    #[test]
    fn ipv6_bind_is_accepted() {
        let listen = from_flags(&["-b", "::1", "-p", "2080"]).listen;
        assert_eq!(listen.addr.to_string(), "[::1]:2080");
        assert!(listen.allow_direct);
    }

    #[test]
    fn repeated_worker_flags_collapse_into_one_list() {
        let settings = from_flags(&["--worker", "a.workers.dev", "--worker", "b.workers.dev"]);
        assert_eq!(settings.workers, "a.workers.dev,b.workers.dev");
    }

    #[test]
    fn repeated_cf_proxy_flags_collapse_into_one_list() {
        let settings = from_flags(&["--cf-proxy", "a.example", "--cf-proxy", "b.example"]);
        assert_eq!(settings.cf_proxies, "a.example,b.example");
        assert!(from_flags(&[]).cf_proxies.is_empty());
    }

    #[test]
    fn no_worker_flag_means_no_domains() {
        assert!(from_flags(&[]).workers.is_empty());
    }

    #[test]
    fn lan_and_explicit_bind_cannot_be_combined() {
        assert!(Args::try_parse_from(["tglock-cli", "--lan", "-b", "127.0.0.1"]).is_err());
    }

    #[test]
    fn a_pinned_secret_file_survives_a_restart() {
        let path = std::env::temp_dir().join(format!(
            "tglock-cli-secret-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);

        let first = from_flags(&["--secret-file", path.to_str().unwrap()])
            .stats()
            .telegram_secret();
        let second = from_flags(&["--secret-file", path.to_str().unwrap()])
            .stats()
            .telegram_secret();

        assert_eq!(
            first, second,
            "a restart must advertise the same tg:// secret"
        );
        assert!(first.starts_with("dd"));

        // A corrupted file must not wedge the daemon: it is replaced.
        std::fs::write(&path, "garbage").unwrap();
        let third = from_flags(&["--secret-file", path.to_str().unwrap()])
            .stats()
            .telegram_secret();
        assert_ne!(third, first);
        let fourth = from_flags(&["--secret-file", path.to_str().unwrap()])
            .stats()
            .telegram_secret();
        assert_eq!(third, fourth, "the replacement must be persisted in turn");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_malformed_values() {
        for bad in [
            vec!["-b", "not-an-ip"],
            vec!["-p", "70000"],
            vec!["-p", "-1"],
            vec!["--unknown"],
        ] {
            assert!(
                Args::try_parse_from(std::iter::once("tglock-cli").chain(bad.iter().copied()))
                    .is_err(),
                "{bad:?} must be rejected"
            );
        }
    }
}
