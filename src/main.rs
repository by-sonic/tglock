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
    /// Падения отдельных маршрутов. Растёт даже когда соединение в итоге
    /// состоялось через запасной адрес (by-sonic/tglock#32).
    route_failures: u32,
    /// Запросы, отклонённые политикой «в LAN-режиме только Telegram».
    ///
    /// Ноль при неработающем телефоне означает, что он вообще не дотянулся до
    /// этой машины; не ноль — что дотянулся, и разбираться надо с адресами
    /// (by-sonic/tglock#42).
    blocked: u32,
    /// Клиенты, которые дошли, но не сумели договориться. Почти всегда это
    /// ссылка `tg://proxy` от прошлого запуска, то есть другой секрет.
    unknown_clients: u32,
    uptime_seconds: u64,
    port: u16,
    /// Адрес, который нужно вписать в Telegram на другом устройстве.
    ///
    /// В LAN-режиме это адрес этого компьютера в локальной сети. Люди искали
    /// его в интерфейсе и не находили: вписывали `127.0.0.1`, который на
    /// телефоне или в эмуляторе означает само устройство, и подключение не
    /// работало (by-sonic/tglock#36).
    share_address: Option<String>,
    logs: Vec<LogLine>,
}

struct AppState {
    stats: Arc<proxy::Stats>,
    settings: Mutex<Settings>,
    active_port: Mutex<u16>,
    /// Слушатель работающего прокси. Нужен, чтобы показать адрес для других
    /// устройств именно тот, на котором прокси реально поднят, а не тот, что
    /// сейчас выбран в настройках.
    active_listen: Mutex<Option<ListenConfig>>,
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
            active_listen: Mutex::new(None),
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
        // События прокси доходят до журнала только здесь: у ядра нет своего
        // способа что-то показать, а интерфейс и так опрашивает состояние.
        for event in self.stats.drain_events() {
            self.log(event, false);
        }
        let data_center = self.stats.last_dc.load(Ordering::Relaxed);
        let route = transport::route_label(self.stats.last_route.load(Ordering::Relaxed));
        StatusSnapshot {
            running: self.stats.running.load(Ordering::SeqCst),
            active_connections: self.stats.active.load(Ordering::Relaxed),
            tunnels: self.stats.ws.load(Ordering::Relaxed),
            data_center: (data_center > 0).then_some(data_center),
            route: route.to_owned(),
            failures: self.stats.ws_failures.load(Ordering::Relaxed),
            route_failures: self.stats.route_failures(),
            blocked: self.stats.blocked.load(Ordering::Relaxed),
            unknown_clients: self.stats.unknown_clients.load(Ordering::Relaxed),
            uptime_seconds: self
                .started_at
                .lock()
                .unwrap()
                .map_or(0, |started| started.elapsed().as_secs()),
            port: *self.active_port.lock().unwrap(),
            share_address: share_address(*self.active_listen.lock().unwrap()),
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

/// Адрес, который нужно вписать в Telegram на другом устройстве.
///
/// Только для слушателя на `0.0.0.0`: на loopback делиться нечем, туда никто
/// извне не достучится. Возвращается адрес этой машины в сети, а не `0.0.0.0`
/// и не `127.0.0.1` — последний на телефоне или в эмуляторе означает само
/// устройство, и именно на этом спотыкались (by-sonic/tglock#36).
fn share_address(listen: Option<ListenConfig>) -> Option<String> {
    listen
        .filter(|listen| listen.addr.ip().is_unspecified())
        .map(|listen| format!("{}:{}", listen.advertised_host(), listen.addr.port()))
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

    *state.active_listen.lock().unwrap() = Some(listen);

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
        *state.active_listen.lock().unwrap() = None;
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
    *state.active_listen.lock().unwrap() = None;
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

/// Environment variables that make the WebView render without a GPU.
///
/// The window is never created when 3D acceleration is unavailable: no
/// monitor, the default Microsoft display driver, a virtual machine without
/// 3D enabled (by-sonic/tglock#10, by-sonic/tglock#17). For a small status
/// panel software rendering costs nothing noticeable, so preferring it is the
/// safer default.
///
/// Values already present in the environment are never overwritten, and
/// `TGLOCK_FORCE_GPU` disables the whole mechanism.
fn software_rendering_vars(
    force_gpu: bool,
    is_set: impl Fn(&str) -> bool,
) -> Vec<(&'static str, &'static str)> {
    if force_gpu {
        return Vec::new();
    }

    let candidates: &[(&str, &str)] = if cfg!(target_os = "windows") {
        &[(
            "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
            "--disable-gpu --disable-gpu-compositing",
        )]
    } else if cfg!(target_os = "macos") {
        // WebKit on macOS falls back to software rendering on its own.
        &[]
    } else {
        &[
            ("WEBKIT_DISABLE_COMPOSITING_MODE", "1"),
            ("WEBKIT_DISABLE_DMABUF_RENDERER", "1"),
        ]
    };

    candidates
        .iter()
        .filter(|(key, _)| !is_set(key))
        .copied()
        .collect()
}

fn prefer_software_rendering() {
    let force_gpu = std::env::var_os("TGLOCK_FORCE_GPU").is_some();
    for (key, value) in software_rendering_vars(force_gpu, |key| std::env::var_os(key).is_some()) {
        std::env::set_var(key, value);
    }
}

fn main() {
    prefer_software_rendering();

    tauri::Builder::default()
        .setup(|app| {
            let settings_path = app
                .path()
                .app_config_dir()
                .map_err(|error| error.to_string())?
                .join("settings.json");
            let state = AppState::new(settings_path);
            // Если секрет не удалось записать, ссылка tg://proxy изменится после
            // перезапуска и Telegram откажется подключаться к сохранённой.
            // Раньше это происходило молча (by-sonic/tglock#37).
            if let Some(error) = state.stats.secret_write_error() {
                state.log(
                    format!("Секрет не сохранён ({error}). После перезапуска ссылка изменится"),
                    true,
                );
            }
            app.manage(state);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_to_share_when_the_proxy_is_off_or_local() {
        assert_eq!(
            share_address(None),
            None,
            "выключенный прокси нечего делить"
        );
        assert_eq!(
            share_address(Some(ListenConfig::loopback(1080))),
            None,
            "на loopback снаружи никто не подключится"
        );
    }

    #[test]
    fn lan_mode_shares_a_reachable_address() {
        let shown = share_address(Some(ListenConfig::lan(1443))).expect("в LAN-режиме адрес нужен");
        assert!(shown.ends_with(":1443"), "порт должен быть виден: {shown}");
        assert!(
            !shown.starts_with("0.0.0.0"),
            "0.0.0.0 нельзя вписать в Telegram: {shown}"
        );
        assert!(
            !shown.starts_with("127.0.0.1"),
            "127.0.0.1 на другом устройстве означает само устройство: {shown}"
        );
    }

    #[test]
    fn software_rendering_is_requested_by_default() {
        let vars = software_rendering_vars(false, |_| false);
        if cfg!(target_os = "macos") {
            assert!(vars.is_empty(), "macOS needs no override");
        } else {
            assert!(
                !vars.is_empty(),
                "a machine without 3D acceleration must still get a window"
            );
        }
    }

    #[test]
    fn force_gpu_disables_the_override() {
        assert!(software_rendering_vars(true, |_| false).is_empty());
    }

    #[test]
    fn an_operators_own_value_is_never_overwritten() {
        assert!(software_rendering_vars(false, |_| true).is_empty());
    }

    #[test]
    fn windows_uses_webview2_arguments_and_linux_uses_webkit_ones() {
        let keys: Vec<_> = software_rendering_vars(false, |_| false)
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        if cfg!(target_os = "windows") {
            assert_eq!(keys, ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"]);
        } else if cfg!(target_os = "linux") {
            assert_eq!(
                keys,
                [
                    "WEBKIT_DISABLE_COMPOSITING_MODE",
                    "WEBKIT_DISABLE_DMABUF_RENDERER"
                ]
            );
        }
    }
}
