fn main() {
    // Only the GUI binary needs Tauri's generated context. Without this guard a
    // headless build would still require the frontend bundle and the WebView
    // toolchain to be present.
    #[cfg(feature = "gui")]
    tauri_build::build();
}
