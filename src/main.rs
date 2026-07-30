#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// The application itself lives in `tglock_lib::gui` because Android loads the crate
// as a shared library and enters through a JNI symbol rather than through
// `main`. Keeping one implementation for both platforms means the desktop
// binary is just this shim.

fn main() {
    tglock_lib::gui::run()
}
