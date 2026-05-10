#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod proxy;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use eframe::egui;

// -- Colors (GitHub Dark inspired) ------------------------------------------

const BG: egui::Color32 = egui::Color32::from_rgb(13, 17, 23);
const SURFACE: egui::Color32 = egui::Color32::from_rgb(22, 27, 34);
const BORDER: egui::Color32 = egui::Color32::from_rgb(48, 54, 61);
const ACCENT: egui::Color32 = egui::Color32::from_rgb(88, 166, 255);
const GREEN: egui::Color32 = egui::Color32::from_rgb(63, 185, 80);
const RED: egui::Color32 = egui::Color32::from_rgb(248, 81, 73);
const TEXT: egui::Color32 = egui::Color32::from_rgb(230, 237, 243);
const TEXT2: egui::Color32 = egui::Color32::from_rgb(139, 148, 158);
const AD_BG: egui::Color32 = egui::Color32::from_rgb(17, 21, 28);

fn main() -> eframe::Result<()> {
    eframe::run_native(
        "TGLock",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([520.0, 620.0])
                .with_min_inner_size([420.0, 500.0])
                .with_title("TGLock"),
            ..Default::default()
        },
        Box::new(|cc| {
            apply_theme(&cc.egui_ctx);
            Ok(Box::new(App::new()))
        }),
    )
}

fn apply_theme(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = SURFACE;
    v.extreme_bg_color = BG;
    v.faint_bg_color = SURFACE;
    v.override_text_color = Some(TEXT);

    v.widgets.noninteractive.bg_fill = SURFACE;
    v.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, TEXT2);
    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER);

    v.widgets.inactive.bg_fill = egui::Color32::from_rgb(33, 38, 45);
    v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, TEXT);
    v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, BORDER);

    v.widgets.hovered.bg_fill = egui::Color32::from_rgb(48, 54, 61);
    v.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, TEXT);

    v.widgets.active.bg_fill = ACCENT;
    v.widgets.active.fg_stroke = egui::Stroke::new(1.0, BG);

    ctx.set_visuals(v);
}

// -- Log --------------------------------------------------------------------

#[derive(Clone)]
struct LogLine {
    ts: String,
    msg: String,
    err: bool,
}

fn now_ts() -> String {
    let s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{:02}:{:02}:{:02}", (s / 3600) % 24, (s / 60) % 60, s % 60)
}

fn log(log: &Arc<Mutex<Vec<LogLine>>>, msg: &str, err: bool) {
    log.lock().unwrap().push(LogLine {
        ts: now_ts(),
        msg: msg.into(),
        err,
    });
}

// -- App --------------------------------------------------------------------

struct App {
    stats: Arc<proxy::Stats>,
    log: Arc<Mutex<Vec<LogLine>>>,
    started_at: Option<Instant>,
    lan_mode: bool,
    port_str: String,
    active_port: u16,
}

impl App {
    fn new() -> Self {
        Self {
            stats: proxy::Stats::new(),
            log: Arc::new(Mutex::new(Vec::new())),
            started_at: None,
            lan_mode: false,
            port_str: proxy::DEFAULT_PORT.to_string(),
            active_port: proxy::DEFAULT_PORT,
        }
    }

    fn running(&self) -> bool {
        self.stats.running.load(Ordering::SeqCst)
    }

    fn start(&mut self) {
        if self.running() { return; }

        let port: u16 = match self.port_str.trim().parse() {
            Ok(p) if p > 0 => p,
            _ => {
                log(&self.log, "Неверный порт", true);
                return;
            }
        };

        self.active_port = port;
        self.started_at = Some(Instant::now());
        let stats = self.stats.clone();
        let lg = self.log.clone();
        let lan = self.lan_mode;

        log(&lg, "Запускаю прокси...", false);

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let r = rt.block_on(proxy::run(stats, lan, port));
            if let Err(e) = r {
                log(&lg, &format!("Ошибка: {}", e), true);
            }
        });

        std::thread::sleep(std::time::Duration::from_millis(250));
        if self.running() {
            let addr = if lan { "0.0.0.0" } else { "127.0.0.1" };
            log(&self.log, &format!("SOCKS5 на {}:{}", addr, port), false);
            if lan {
                log(&self.log, "LAN-режим: другие устройства могут подключаться", false);
            }
        }
    }

    fn stop(&mut self) {
        self.stats.running.store(false, Ordering::SeqCst);
        self.started_at = None;
        log(&self.log, "Остановлен", false);
    }

    fn uptime_str(&self) -> String {
        match self.started_at {
            Some(t) => {
                let s = t.elapsed().as_secs();
                format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
            }
            None => "--:--:--".into(),
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(std::time::Duration::from_millis(300));

        let on = self.running();
        let active = self.stats.active.load(Ordering::Relaxed);
        let total = self.stats.total.load(Ordering::Relaxed);
        let ws = self.stats.ws.load(Ordering::Relaxed);
        let dc = self.stats.last_dc.load(Ordering::Relaxed);

        // === Ad bar (top) ===
        egui::TopBottomPanel::top("ad").show(ctx, |ui| {
            egui::Frame::new()
                .fill(AD_BG)
                .inner_margin(egui::Margin::symmetric(12, 6))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.colored_label(ACCENT, egui::RichText::new("RoseVPN").size(12.0).strong());
                        ui.colored_label(TEXT2, egui::RichText::new("Обход для всех приложений").size(11.0));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(egui::Button::new(
                                egui::RichText::new("@rosevpnru_bot").size(11.0).strong().color(ACCENT)
                            ).frame(false)).clicked() {
                                let _ = open::that("https://t.me/rosevpnru_bot");
                            }
                        });
                    });
                });
        });

        // === Log (bottom) ===
        egui::TopBottomPanel::bottom("log")
            .min_height(120.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.colored_label(TEXT2, egui::RichText::new("LOG").size(11.0));
                ui.separator();
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for e in self.log.lock().unwrap().iter() {
                            let c = if e.err { RED } else { TEXT2 };
                            ui.colored_label(c, egui::RichText::new(
                                format!("{} {}", e.ts, e.msg)
                            ).size(11.5).monospace());
                        }
                    });
            });

        // === Stats bar ===
        egui::TopBottomPanel::bottom("stats").show(ctx, |ui| {
            egui::Frame::new()
                .fill(SURFACE)
                .inner_margin(egui::Margin::symmetric(16, 8))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        stat(ui, "Соединения", &active.to_string());
                        ui.add_space(20.0);
                        stat(ui, "WS-туннели", &ws.to_string());
                        ui.add_space(20.0);
                        stat(ui, "DC", &if dc > 0 { dc.to_string() } else { "—".into() });
                        ui.add_space(20.0);
                        stat(ui, "Всего", &total.to_string());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            stat(ui, "Аптайм", &self.uptime_str());
                        });
                    });
                });
        });

        // === Main ===
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(30.0);

                // Title
                ui.colored_label(TEXT, egui::RichText::new("TGLock").size(32.0).strong());
                ui.add_space(4.0);
                ui.colored_label(TEXT2, egui::RichText::new("WebSocket-туннель для Telegram").size(13.0));

                ui.add_space(24.0);

                // Status indicator
                let (dot_color, status_text) = if on {
                    (GREEN, "Подключено")
                } else {
                    (egui::Color32::from_rgb(80, 80, 80), "Отключено")
                };

                ui.horizontal(|ui| {
                    let center = ui.available_width() / 2.0 - 50.0;
                    ui.add_space(center);
                    let (r, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                    ui.painter().circle_filled(r.center(), 5.0, dot_color);
                    ui.colored_label(
                        if on { GREEN } else { TEXT2 },
                        egui::RichText::new(status_text).size(14.0).strong(),
                    );
                });

                ui.add_space(20.0);

                // Options (only when stopped)
                if !on {
                    ui.horizontal(|ui| {
                        let center = ui.available_width() / 2.0 - 130.0;
                        ui.add_space(center);
                        ui.colored_label(TEXT2, egui::RichText::new("Порт:").size(12.0));
                        let port_edit = egui::TextEdit::singleline(&mut self.port_str)
                            .desired_width(55.0)
                            .font(egui::TextStyle::Monospace);
                        ui.add(port_edit);
                        ui.add_space(12.0);
                        ui.checkbox(&mut self.lan_mode, "");
                        ui.colored_label(TEXT2, egui::RichText::new("LAN").size(12.0));
                        ui.colored_label(
                            egui::Color32::from_rgb(80, 85, 95),
                            egui::RichText::new("(0.0.0.0)").size(10.5),
                        );
                    });
                    ui.add_space(8.0);
                }

                // Big button
                if !on {
                    let btn = ui.add_sized(
                        [260.0, 52.0],
                        egui::Button::new(
                            egui::RichText::new("ПОДКЛЮЧИТЬ").size(18.0).strong().color(BG)
                        ).fill(ACCENT).corner_radius(8.0),
                    );
                    if btn.clicked() {
                        self.start();
                    }
                } else {
                    let btn = ui.add_sized(
                        [260.0, 52.0],
                        egui::Button::new(
                            egui::RichText::new("ОТКЛЮЧИТЬ").size(18.0).strong().color(TEXT)
                        ).fill(egui::Color32::from_rgb(40, 45, 52)).corner_radius(8.0),
                    );
                    if btn.clicked() {
                        self.stop();
                    }
                }

                ui.add_space(24.0);

                // Setup section
                egui::Frame::new()
                    .fill(SURFACE)
                    .corner_radius(8.0)
                    .inner_margin(16.0)
                    .show(ui, |ui| {
                        ui.set_width(360.0);

                        ui.colored_label(TEXT, egui::RichText::new("Настройка Telegram").size(14.0).strong());
                        ui.add_space(6.0);

                        let server_addr = if self.lan_mode && on {
                            local_ip().unwrap_or_else(|| "127.0.0.1".into())
                        } else {
                            "127.0.0.1".into()
                        };

                        let display_port = if on { self.active_port } else {
                            self.port_str.trim().parse().unwrap_or(proxy::DEFAULT_PORT)
                        };

                        if on {
                            if ui.add(egui::Button::new(
                                egui::RichText::new("Настроить автоматически").size(13.0).color(ACCENT)
                            ).frame(false)).clicked() {
                                let _ = open::that(format!("tg://socks?server={}&port={}", server_addr, display_port));
                                log(&self.log, "Открываю настройку Telegram...", false);
                            }
                            ui.add_space(4.0);
                        }

                        ui.colored_label(TEXT2, egui::RichText::new("Настройки → Продвинутые → Тип соединения → SOCKS5").size(11.5));
                        ui.add_space(4.0);

                        egui::Grid::new("cfg").num_columns(2).spacing([12.0, 3.0]).show(ui, |ui| {
                            ui.colored_label(TEXT2, "Сервер");
                            ui.monospace(&server_addr);
                            ui.end_row();
                            ui.colored_label(TEXT2, "Порт");
                            ui.monospace(format!("{}", display_port));
                            ui.end_row();
                        });
                    });

                ui.add_space(16.0);

                // How it works (compact)
                ui.colored_label(TEXT2, egui::RichText::new(
                    "Трафик Telegram → SOCKS5 → WSS → web.telegram.org → DC"
                ).size(11.0));
                ui.colored_label(TEXT2, egui::RichText::new(
                    "Провайдер видит обычный HTTPS. Остальной трафик не затрагивается."
                ).size(11.0));
            });
        });
    }
}

fn stat(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.vertical(|ui| {
        ui.colored_label(TEXT2, egui::RichText::new(label).size(10.0));
        ui.colored_label(TEXT, egui::RichText::new(value).size(13.0).strong().monospace());
    });
}

fn local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}
