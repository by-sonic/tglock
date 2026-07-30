#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tauri::{Manager, State};
use tglock::config::ListenConfig;
use tglock::{proxy, transport};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Settings {
    lan_mode: bool,
    port: u16,
    worker_domain: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            lan_mode: false,
            port: proxy::DEFAULT_PORT,
            worker_domain: String::new(),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LogLine {
    timestamp: String,
    message: String,
    error: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusSnapshot {
    running: bool,
    active_connections: u32,
    tunnels: u32,
    data_center: Option<u16>,
    route: String,
    failures: u32,
    uptime_seconds: u64,
    port: u16,
    logs: Vec<LogLine>,
}

struct AppState {
    stats: Arc<proxy::Stats>,
    settings: Mutex<Settings>,
    active_port: Mutex<u16>,
    started_at: Mutex<Option<Instant>>,
    logs: Arc<Mutex<Vec<LogLine>>>,
    settings_path: PathBuf,
}

impl AppState {
    fn new(settings_path: PathBuf) -> Self {
        let settings = std::fs::read(&settings_path)
            .ok()
            .and_then(|contents| serde_json::from_slice(&contents).ok())
            .unwrap_or_default();
        Self {
            stats: proxy::Stats::new(),
            settings: Mutex::new(settings),
            active_port: Mutex::new(proxy::DEFAULT_PORT),
            started_at: Mutex::new(None),
            logs: Arc::new(Mutex::new(Vec::new())),
            settings_path,
        }
    }

    fn log(&self, message: impl Into<String>, error: bool) {
        let mut logs = self.logs.lock().unwrap();
        logs.push(LogLine {
            timestamp: current_time(),
            message: message.into(),
            error,
        });
        if logs.len() > 100 {
            logs.remove(0);
        }
    }

    fn snapshot(&self) -> StatusSnapshot {
        let data_center = self.stats.last_dc.load(Ordering::Relaxed);
        let route = transport::route_label(self.stats.last_route.load(Ordering::Relaxed));
        StatusSnapshot {
            running: self.stats.running.load(Ordering::SeqCst),
            active_connections: self.stats.active.load(Ordering::Relaxed),
            tunnels: self.stats.ws.load(Ordering::Relaxed),
            data_center: (data_center > 0).then_some(data_center),
            route: route.to_owned(),
            failures: self.stats.ws_failures.load(Ordering::Relaxed),
            uptime_seconds: self
                .started_at
                .lock()
                .unwrap()
                .map_or(0, |started| started.elapsed().as_secs()),
            port: *self.active_port.lock().unwrap(),
            logs: self.logs.lock().unwrap().clone(),
        }
    }

    fn persist_settings(&self, settings: &Settings) -> Result<(), String> {
        if let Some(parent) = self.settings_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("Не удалось создать папку настроек: {error}"))?;
        }
        let contents = serde_json::to_vec_pretty(settings)
            .map_err(|error| format!("Не удалось сохранить настройки: {error}"))?;
        std::fs::write(&self.settings_path, contents)
            .map_err(|error| format!("Не удалось сохранить настройки: {error}"))
    }
}

fn current_time() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        (seconds / 3600) % 24,
        (seconds / 60) % 60,
        seconds % 60
    )
}

#[tauri::command]
fn get_status(state: State<'_, AppState>) -> StatusSnapshot {
    state.snapshot()
}

#[tauri::command]
fn get_settings(state: State<'_, AppState>) -> Settings {
    state.settings.lock().unwrap().clone()
}

#[tauri::command]
fn save_settings(settings: Settings, state: State<'_, AppState>) -> Result<Settings, String> {
    if state.stats.running.load(Ordering::SeqCst) {
        return Err("Сначала выключите защиту".into());
    }
    if settings.port == 0 {
        return Err("Порт должен быть от 1 до 65535".into());
    }
    state.persist_settings(&settings)?;
    *state.settings.lock().unwrap() = settings.clone();
    state.log("Настройки сохранены", false);
    Ok(settings)
}

#[tauri::command]
fn start_proxy(state: State<'_, AppState>) -> Result<StatusSnapshot, String> {
    if state.stats.running.load(Ordering::SeqCst) {
        return Ok(state.snapshot());
    }

    let settings = state.settings.lock().unwrap().clone();
    state.stats.set_worker_domain(&settings.worker_domain);
    *state.active_port.lock().unwrap() = settings.port;
    *state.started_at.lock().unwrap() = Some(Instant::now());
    state.log("Запускаю защищённый маршрут…", false);

    let listen = if settings.lan_mode {
        ListenConfig::lan(settings.port)
    } else {
        ListenConfig::loopback(settings.port)
    };

    let stats = state.stats.clone();
    let logs = state.logs.clone();
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(runtime) => runtime,
            Err(error) => {
                push_log(&logs, format!("Не удалось запустить сервис: {error}"), true);
                return;
            }
        };
        if let Err(error) = runtime.block_on(proxy::run(stats, listen)) {
            push_log(&logs, format!("Ошибка подключения: {error}"), true);
        }
    });

    std::thread::sleep(std::time::Duration::from_millis(220));
    if !state.stats.running.load(Ordering::SeqCst) {
        *state.started_at.lock().unwrap() = None;
        return Err(state
            .logs
            .lock()
            .unwrap()
            .last()
            .map(|line| line.message.clone())
            .unwrap_or_else(|| "Не удалось запустить прокси".into()));
    }

    state.log(format!("Прокси запущен на {}", listen.addr), false);
    let _ = open::that(listen.telegram_link(&state.stats.telegram_secret()));
    state.log("Открываю подключение в Telegram…", false);
    Ok(state.snapshot())
}

#[tauri::command]
fn stop_proxy(state: State<'_, AppState>) -> StatusSnapshot {
    state.stats.stop();
    *state.started_at.lock().unwrap() = None;
    state.log("Защита выключена", false);
    state.snapshot()
}

fn push_log(logs: &Arc<Mutex<Vec<LogLine>>>, message: String, error: bool) {
    logs.lock().unwrap().push(LogLine {
        timestamp: current_time(),
        message,
        error,
    });
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let settings_path = app
                .path()
                .app_config_dir()
                .map_err(|error| error.to_string())?
                .join("settings.json");
            app.manage(AppState::new(settings_path));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            get_settings,
            save_settings,
            start_proxy,
            stop_proxy
        ])
        .run(tauri::generate_context!())
        .expect("failed to run TGLock");
}
