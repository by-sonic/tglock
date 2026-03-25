#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use eframe::egui;
use tg_unblock::{bypass, network, ws_proxy};

const PROXY_PORT: u16 = 1080;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([680.0, 560.0])
            .with_min_inner_size([580.0, 460.0])
            .with_title("TG Unblock"),
        ..Default::default()
    };

    eframe::run_native(
        "TG Unblock",
        options,
        Box::new(|cc| {
            setup_fonts(&cc.egui_ctx);
            Ok(Box::new(App::new()))
        }),
    )
}

#[cfg(target_os = "windows")]
fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "system".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(include_bytes!(
            "C:\\Windows\\Fonts\\segoeui.ttf"
        ))),
    );
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "system".to_owned());
    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .insert(0, "system".to_owned());
    ctx.set_fonts(fonts);
}

#[cfg(not(target_os = "windows"))]
fn setup_fonts(_ctx: &egui::Context) {}

#[derive(Clone)]
struct LogEntry {
    text: String,
    is_error: bool,
    ts: String,
}

struct App {
    log: Arc<Mutex<Vec<LogEntry>>>,
    proxy_stats: Arc<ws_proxy::ProxyStats>,
    is_admin: bool,
    adapter_name: Arc<Mutex<Option<String>>>,
    dns_set: Arc<Mutex<bool>>,
}

impl App {
    fn new() -> Self {
        let is_admin = bypass::check_admin();
        let app = Self {
            log: Arc::new(Mutex::new(Vec::new())),
            proxy_stats: ws_proxy::ProxyStats::new(),
            is_admin,
            adapter_name: Arc::new(Mutex::new(None)),
            dns_set: Arc::new(Mutex::new(false)),
        };
        log_msg(&app.log, "Запущено", false);
        if !is_admin {
            log_msg(&app.log, "Нет прав администратора — DNS менять не получится", true);
        }
        {
            let adapter = app.adapter_name.clone();
            let log = app.log.clone();
            std::thread::spawn(move || {
                if let Some(name) = network::detect_adapter() {
                    log_msg(&log, &format!("Адаптер: {}", name), false);
                    *adapter.lock().unwrap() = Some(name);
                }
            });
        }
        app
    }

    fn proxy_running(&self) -> bool {
        self.proxy_stats.running.load(Ordering::SeqCst)
    }

    fn start_proxy(&self) {
        if self.proxy_running() {
            return;
        }
        let stats = self.proxy_stats.clone();
        let log = self.log.clone();
        let adapter = self.adapter_name.clone();
        let dns_set = self.dns_set.clone();
        let is_admin = self.is_admin;

        std::thread::spawn(move || {
            // DNS
            if is_admin {
                let aname = adapter.lock().unwrap().clone().or_else(network::detect_adapter);
                if let Some(ref name) = aname {
                    if bypass::set_dns(name, "1.1.1.1", "1.0.0.1").is_ok() {
                        bypass::flush_dns();
                        log_msg(&log, "DNS → Cloudflare 1.1.1.1", false);
                        *dns_set.lock().unwrap() = true;
                    }
                }
            }

            log_msg(&log, &format!("Запускаю WS-прокси на 127.0.0.1:{}...", PROXY_PORT), false);

            let rt = tokio::runtime::Runtime::new().unwrap();
            let result = rt.block_on(ws_proxy::run_proxy_bind("127.0.0.1", PROXY_PORT, stats));
            if let Err(e) = result {
                log_msg(&log, &format!("Прокси остановлен: {}", e), true);
            }
        });

        std::thread::sleep(std::time::Duration::from_millis(300));
        if self.proxy_running() {
            log_msg(&self.log, "Прокси запущен! Настройте Telegram.", false);
        }
    }

    fn stop_proxy(&self) {
        self.proxy_stats.running.store(false, Ordering::SeqCst);
        log_msg(&self.log, "Прокси остановлен", false);

        if *self.dns_set.lock().unwrap() {
            let adapter = self.adapter_name.clone();
            let log = self.log.clone();
            let dns_set = self.dns_set.clone();
            std::thread::spawn(move || {
                let aname = adapter.lock().unwrap().clone().or_else(network::detect_adapter);
                if let Some(ref name) = aname {
                    let _ = bypass::reset_dns(name);
                    bypass::flush_dns();
                    *dns_set.lock().unwrap() = false;
                    log_msg(&log, "DNS сброшен", false);
                }
            });
        }
    }

    fn open_tg_proxy_link(&self) {
        let url = format!("tg://socks?server=127.0.0.1&port={}", PROXY_PORT);
        log_msg(&self.log, "Открываю настройку прокси в Telegram...", false);
        let _ = open::that(&url);
    }
}

fn log_msg(log: &Arc<Mutex<Vec<LogEntry>>>, text: &str, err: bool) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ts = format!("{:02}:{:02}:{:02}", (now % 86400) / 3600, (now % 3600) / 60, now % 60);
    log.lock().unwrap().push(LogEntry {
        text: text.to_string(),
        is_error: err,
        ts,
    });
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(std::time::Duration::from_millis(400));

        let running = self.proxy_running();
        let active = self.proxy_stats.active_conn.load(Ordering::Relaxed);
        let total = self.proxy_stats.total_conn.load(Ordering::Relaxed);
        let ws = self.proxy_stats.ws_active.load(Ordering::Relaxed);

        // --- Top bar ---
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("TG Unblock");
                ui.separator();
                if running {
                    ui.colored_label(
                        egui::Color32::from_rgb(80, 220, 120),
                        egui::RichText::new("ПРОКСИ РАБОТАЕТ").strong(),
                    );
                    ui.separator();
                    ui.label(format!("Соединений: {} (WS: {}) | Всего: {}", active, ws, total));
                } else {
                    ui.label("Прокси не запущен");
                }
            });
        });

        // --- Log panel ---
        egui::TopBottomPanel::bottom("log")
            .min_height(130.0)
            .show(ctx, |ui| {
                ui.label(egui::RichText::new("Лог").strong());
                ui.separator();
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        let logs = self.log.lock().unwrap();
                        for e in logs.iter() {
                            let color = if e.is_error {
                                egui::Color32::from_rgb(255, 100, 100)
                            } else {
                                egui::Color32::from_rgb(170, 215, 170)
                            };
                            ui.colored_label(color, format!("[{}] {}", e.ts, e.text));
                        }
                    });
            });

        // --- Main panel ---
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(10.0);

            // --- VPN ad (top) ---
            ui.vertical_centered(|ui| {
                egui::Frame::new()
                    .fill(egui::Color32::from_rgb(25, 30, 42))
                    .corner_radius(8.0)
                    .inner_margin(egui::Margin::symmetric(14, 8))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.colored_label(
                                egui::Color32::from_rgb(100, 180, 255),
                                egui::RichText::new("by sonic VPN").size(13.0).strong(),
                            );
                            ui.label(
                                egui::RichText::new("Полный обход для всех приложений")
                                    .size(12.0)
                                    .color(egui::Color32::from_rgb(160, 165, 180)),
                            );
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.add(
                                    egui::Button::new(
                                        egui::RichText::new("@bysonicvpn_bot")
                                            .size(12.0)
                                            .strong()
                                            .color(egui::Color32::from_rgb(100, 200, 255)),
                                    )
                                    .frame(false),
                                ).clicked() {
                                    let _ = open::that("https://t.me/bysonicvpn_bot");
                                }
                            });
                        });
                    });
            });

            ui.add_space(12.0);

            ui.vertical_centered(|ui| {
                if !running {
                    ui.label(egui::RichText::new("Обход блокировки Telegram через WebSocket-прокси").size(15.0));
                    ui.add_space(5.0);
                    ui.label("Трафик идёт через web.telegram.org — провайдер видит обычный HTTPS");
                    ui.add_space(15.0);

                    let btn = ui.add_sized(
                        [340.0, 55.0],
                        egui::Button::new(egui::RichText::new("Запустить обход").size(20.0).strong()),
                    );
                    if btn.clicked() {
                        self.start_proxy();
                    }
                } else {
                    ui.colored_label(
                        egui::Color32::from_rgb(80, 220, 120),
                        egui::RichText::new("Обход работает").size(22.0).strong(),
                    );
                    ui.add_space(5.0);
                    ui.label(format!("SOCKS5 прокси на 127.0.0.1:{}", PROXY_PORT));
                    ui.label(format!("WebSocket-туннелей: {} | Соединений: {}", ws, active));
                    ui.add_space(12.0);

                    // Stop button
                    let stop = ui.add_sized(
                        [340.0, 42.0],
                        egui::Button::new(egui::RichText::new("Остановить").size(17.0)),
                    );
                    if stop.clicked() {
                        self.stop_proxy();
                    }
                }
            });

            ui.add_space(20.0);
            ui.separator();
            ui.add_space(8.0);

            // --- Telegram setup ---
            ui.heading("Настройка Telegram Desktop");
            ui.add_space(6.0);

            if running {
                ui.horizontal(|ui| {
                    if ui.button("   Настроить автоматически   ").clicked() {
                        self.open_tg_proxy_link();
                    }
                    ui.label("(откроет Telegram, нажмите \"Подключить\")");
                });
                ui.add_space(8.0);
            }

            ui.label("Или вручную: Настройки → Продвинутые → Тип соединения → SOCKS5");
            ui.add_space(4.0);
            egui::Grid::new("manual_setup")
                .num_columns(2)
                .spacing([15.0, 4.0])
                .show(ui, |ui| {
                    ui.label("Сервер:");
                    ui.monospace("127.0.0.1");
                    ui.end_row();
                    ui.label("Порт:");
                    ui.monospace(format!("{}", PROXY_PORT));
                    ui.end_row();
                    ui.label("Логин/Пароль:");
                    ui.label("оставить пустыми");
                    ui.end_row();
                });

            ui.add_space(15.0);
            ui.separator();
            ui.add_space(5.0);

            // --- How it works ---
            ui.heading("Как это работает");
            ui.add_space(4.0);
            ui.label("1. Локальный SOCKS5-прокси принимает соединения от Telegram");
            ui.label("2. Трафик к серверам Telegram заворачивается в WebSocket (WSS)");
            ui.label("3. Подключение идёт через web.telegram.org — обычный HTTPS");
            ui.label("4. Провайдер/DPI не видит MTProto, не может замедлить");
            ui.add_space(4.0);
            ui.colored_label(
                egui::Color32::from_rgb(170, 170, 170),
                "Не-Telegram трафик проходит напрямую без изменений",
            );

        });
    }
}
