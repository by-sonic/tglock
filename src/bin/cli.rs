use std::sync::atomic::Ordering;
use std::net::IpAddr;

use clap::Parser;
use tg_unblock::{bypass, network, ws_proxy};

#[derive(Parser)]
#[command(name = "tg_unblock", version, about = "Обход блокировки Telegram через WebSocket-туннель")]
struct Args {
    /// Порт SOCKS5-прокси
    #[arg(short, long, default_value_t = 1080)]
    port: u16,

    /// Адрес привязки
    #[arg(short, long, default_value = "127.0.0.1")]
    bind: String,

    /// Сменить DNS на Cloudflare 1.1.1.1 (нужен root/admin)
    #[arg(long)]
    dns: bool
}

fn main() {
    let args = Args::parse();

    // Validate bind address early
    if args.bind.parse::<IpAddr>().is_err() {
        eprintln!("[!] Неверный адрес привязки: {}", args.bind);
        std::process::exit(1);
    }

    let is_admin = bypass::check_admin();
    let mut dns_was_set = false;
    let mut adapter_name: Option<String> = None;

    // DNS setup
    if args.dns {
        if !is_admin {
            eprintln!("[!] Для смены DNS нужны права root/администратора");
        } else {
            adapter_name = network::detect_adapter();
            if let Some(ref name) = adapter_name {
                match bypass::set_dns(name, "1.1.1.1", "1.0.0.1") {
                    Ok(()) => {
                        bypass::flush_dns();
                        eprintln!("[+] DNS -> Cloudflare 1.1.1.1 (адаптер: {})", name);
                        dns_was_set = true;
                    }
                    Err(e) => eprintln!("[!] Не удалось сменить DNS: {}", e),
                }
            } else {
                eprintln!("[!] Не удалось определить сетевой адаптер");
            }
        }
    }

    let stats = ws_proxy::ProxyStats::new();
    stats.verbose.store(true, std::sync::atomic::Ordering::Relaxed);
    let stats_signal = stats.clone();

    eprintln!("[*] Запускаю SOCKS5-прокси на {}:{}...", args.bind, args.port);
    eprintln!("[*] Подключение прокси в Telegram:");
    eprintln!("    tg://socks?server={}&port={}", args.bind, args.port);
    eprintln!("[*] Ctrl+C для остановки");

    let rt = tokio::runtime::Runtime::new().expect("Не удалось создать tokio runtime");

    rt.block_on(async {
        // Graceful shutdown по Ctrl+C
        let stats_ctrl = stats_signal.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            eprintln!("\n[*] Остановка...");
            stats_ctrl.running.store(false, Ordering::SeqCst);
        });

        if let Err(e) = ws_proxy::run_proxy_bind(&args.bind, args.port, stats_signal).await {
            eprintln!("[!] Прокси остановлен с ошибкой: {}", e);
        }
    });

    // Cleanup DNS
    if dns_was_set {
        let name = adapter_name.or_else(network::detect_adapter);
        if let Some(ref name) = name {
            let _ = bypass::reset_dns(name);
            bypass::flush_dns();
            eprintln!("[+] DNS сброшен");
        }
    }

    eprintln!("[*] Завершено. Всего соединений: {}", stats.total_conn.load(Ordering::Relaxed));
}
