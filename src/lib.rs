//! TGLock core: the MTProto/WebSocket transport shared by the desktop GUI and
//! the headless CLI.
//!
//! With the `gui` feature disabled this crate does not depend on Tauri, so the
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

/// Desktop and Android graphical application; absent from headless builds.
#[cfg(feature = "gui")]
pub mod gui;
