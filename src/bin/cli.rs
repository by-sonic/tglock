//! TGLock without a graphical interface.
//!
//! Built with `--no-default-features` this binary links neither Tauri nor a
//! system WebView, so it runs on servers, in containers and on machines with no
//! GPU or monitor — the cases that make the GUI fail to start at all
//! (by-sonic/tglock#10, by-sonic/tglock#17).

use clap::Parser;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tglock::config::ListenConfig;
use tglock::{mtproto, proxy, transport};

const STATUS_POLL: Duration = Duration::from_secs(1);

#[derive(Debug, Parser)]
#[command(
    name = "tglock-cli",
    version,
    about = "TGLock без графического интерфейса: локальный MTProto-прокси через WebSocket"
)]
struct Args {
    /// Адрес для прослушивания. 127.0.0.1 — только этот компьютер
    #[arg(short, long, value_name = "IP", default_value = "127.0.0.1")]
    bind: IpAddr,

    /// Порт локального прокси
    #[arg(short, long, value_name = "PORT", default_value_t = proxy::DEFAULT_PORT)]
    port: u16,

    /// То же, что --bind 0.0.0.0: доступ с других устройств в локальной сети
    #[arg(long, conflicts_with = "bind")]
    lan: bool,

    /// Домен своего Cloudflare Worker как резервный маршрут. Можно повторять
    #[arg(long, value_name = "DOMAIN")]
    worker: Vec<String>,

    /// Проксировать и не-Telegram адреса. На сетевом адресе это открытый SOCKS5
    #[arg(long)]
    allow_direct: bool,

    /// Файл с секретом прокси. Обязателен для сервиса: иначе после перезапуска
    /// секрет будет новым и уже настроенные клиенты перестанут подключаться
    #[arg(long, value_name = "PATH")]
    secret_file: Option<PathBuf>,

    /// Печатать только ошибки
    #[arg(short, long)]
    quiet: bool,
}

impl Args {
    fn stats(&self) -> Arc<proxy::Stats> {
        match &self.secret_file {
            Some(path) => proxy::Stats::with_secret(mtproto::load_or_create_secret_at(path)),
            None => proxy::Stats::new(),
        }
    }

    fn listen(&self) -> ListenConfig {
        let base = if self.lan {
            ListenConfig::lan(self.port)
        } else {
            ListenConfig::new(self.bind, self.port)
        };
        if self.allow_direct {
            base.with_allow_direct(true)
        } else {
            base
        }
    }

    fn worker_domains(&self) -> String {
        self.worker.join(",")
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
    let listen = args.listen();
    let stats = args.stats();
    stats.set_worker_domain(&args.worker_domains());

    // Bind before printing anything: a busy port must be an error, not a
    // daemon that reports success and silently does nothing.
    let listener = proxy::bind(listen).await?;

    if !args.quiet {
        println!("Слушаю {}", listen.addr);
        println!(
            "Ссылка для Telegram: {}",
            listen.telegram_link(&stats.telegram_secret())
        );
        if listen.allow_direct && !listen.addr.ip().is_loopback() {
            println!(
                "Внимание: --allow-direct на адресе {} превращает TGLock в открытый SOCKS5-прокси",
                listen.addr.ip()
            );
        } else if !listen.allow_direct {
            println!("Пропускаю только адреса Telegram");
        }
        if !args.worker.is_empty() {
            println!("Резервные Worker-домены: {}", args.worker_domains());
        }
    }

    let server_stats = stats.clone();
    let mut server =
        tokio::spawn(
            async move { proxy::serve(server_stats, listener, listen.allow_direct).await },
        );
    let watcher = (!args.quiet).then(|| tokio::spawn(watch_status(stats.clone())));

    let outcome = tokio::select! {
        joined = &mut server => joined.map_err(|error| format!("рабочая задача упала: {error}"))?,
        signal = shutdown_signal() => {
            signal.map_err(|error| format!("обработчик сигналов: {error}"))?;
            if !args.quiet {
                println!("Получен сигнал остановки, закрываю соединения…");
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
        let current = (
            stats.active.load(Ordering::Relaxed),
            stats.ws.load(Ordering::Relaxed),
            stats.last_dc.load(Ordering::Relaxed),
            stats.last_route.load(Ordering::Relaxed),
            stats.ws_failures.load(Ordering::Relaxed),
        );
        if previous.as_ref() == Some(&current) {
            continue;
        }
        let (active, tunnels, dc, route, failures) = current;
        println!(
            "соединений {active} · туннелей {tunnels} · {} · {} · сбоев {failures}",
            if dc > 0 {
                format!("DC{dc}")
            } else {
                "DC не определён".to_owned()
            },
            transport::route_label(route)
        );
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

    #[test]
    fn command_definition_is_valid() {
        Args::command().debug_assert();
    }

    #[test]
    fn defaults_to_loopback_on_the_default_port() {
        let listen = parse(&[]).listen();
        assert_eq!(listen.addr.to_string(), "127.0.0.1:1080");
        assert!(listen.allow_direct);
    }

    #[test]
    fn lan_flag_matches_explicit_wildcard_bind() {
        assert_eq!(
            parse(&["--lan"]).listen(),
            parse(&["-b", "0.0.0.0"]).listen()
        );
    }

    #[test]
    fn lan_does_not_relay_non_telegram_traffic() {
        let listen = parse(&["--lan"]).listen();
        assert_eq!(listen.addr.to_string(), "0.0.0.0:1080");
        assert!(!listen.allow_direct);
    }

    #[test]
    fn allow_direct_is_the_only_way_to_open_a_network_listener() {
        assert!(!parse(&["-b", "192.168.1.10"]).listen().allow_direct);
        assert!(
            parse(&["-b", "192.168.1.10", "--allow-direct"])
                .listen()
                .allow_direct
        );
    }

    #[test]
    fn bind_and_port_are_honoured() {
        let listen = parse(&["--bind", "10.0.0.7", "--port", "1443"]).listen();
        assert_eq!(listen.addr.to_string(), "10.0.0.7:1443");
    }

    #[test]
    fn ipv6_bind_is_accepted() {
        let listen = parse(&["-b", "::1", "-p", "2080"]).listen();
        assert_eq!(listen.addr.to_string(), "[::1]:2080");
        assert!(listen.allow_direct);
    }

    #[test]
    fn repeated_worker_flags_collapse_into_one_list() {
        let args = parse(&["--worker", "a.workers.dev", "--worker", "b.workers.dev"]);
        assert_eq!(args.worker_domains(), "a.workers.dev,b.workers.dev");
    }

    #[test]
    fn no_worker_flag_means_no_domains() {
        assert!(parse(&[]).worker_domains().is_empty());
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

        let first = parse(&["--secret-file", path.to_str().unwrap()])
            .stats()
            .telegram_secret();
        let second = parse(&["--secret-file", path.to_str().unwrap()])
            .stats()
            .telegram_secret();

        assert_eq!(
            first, second,
            "a restart must advertise the same tg:// secret"
        );
        assert!(first.starts_with("dd"));

        // A corrupted file must not wedge the daemon: it is replaced.
        std::fs::write(&path, "garbage").unwrap();
        let third = parse(&["--secret-file", path.to_str().unwrap()])
            .stats()
            .telegram_secret();
        assert_ne!(third, first);
        let fourth = parse(&["--secret-file", path.to_str().unwrap()])
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
