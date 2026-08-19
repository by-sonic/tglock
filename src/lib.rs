//! TGLock core: the MTProto/WebSocket transport shared by the desktop GUI and
//! the headless CLI.
//!
//! Nothing in this crate depends on Tauri or on a windowing system, so the
//! `tglock-cli` binary can be built with `--no-default-features` on a server
//! that has neither a GPU nor a monitor.

pub mod config;
pub mod mtproto;
pub mod proxy;
pub mod telegram_net;
pub mod transport;

/// Настройки headless-версии: файл конфигурации и сведение с флагами.
#[cfg(feature = "cli")]
pub mod cli_settings;
