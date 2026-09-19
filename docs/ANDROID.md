# Android (experimental)

Issue #9 is implemented as a Tauri Android application sharing the current Rust
proxy engine and UI with the desktop application. The old Android PR scaffold is
retained, but its stale engine and desktop code are not imported.

## Install a test APK

Open this PR's **Android APK** check, then the workflow run's **Artifacts** section.
Download `tglock-android-arm64-debug`, unzip it, and install the `.apk` on an
ARM64 Android 7.0+ device. GitHub requires signing in to download CI artifacts.
No compiler or Android Studio is needed on the phone. The artifact expires after
14 days; maintainers can rerun the workflow to create a fresh build.

This is an automatically debug-signed test build, not a Play Store release.
Different CI runs can use different debug signing keys: if Android rejects an
update because the signatures differ, uninstall the previous test build first.
Uninstalling deletes settings and changes the proxy secret, so reconnect Telegram
with the new link. A future production release needs a stable signing key.

1. Open TGLock and press **Включить защиту**.
2. Accept the proxy in Telegram when prompted. If opening Telegram fails, return
   to TGLock and use **Открыть Telegram** or **Скопировать ссылку**.
3. Keep LAN access off when Telegram runs on this same phone (`127.0.0.1`).
4. To stop, return through the ongoing notification and press **Выключить**.

## Lifecycle and limitations

The native foreground service starts only for an explicitly started proxy and
stops when its Rust accept loop finishes, including a normal Stop action. It is
not stopped by Activity destruction or rotation. Android 14+ declares the
`specialUse` service type, its dedicated permission, and a subtype describing the
user-controlled local proxy. Notification permission denial does not prevent the
foreground service from running; Android still exposes it in its task manager.

The service uses `START_NOT_STICKY`: after Android kills the process or the user
force-stops it, it does not restart a notification without a Rust engine. Open
TGLock and enable protection again. No boot receiver or automatic background
restart is installed. Vendor battery management and network changes may still
interrupt connections. The app does not claim to be a device-wide VPN.

The proxy secret lives in the app's private configuration directory. Desktop
installs migrate an existing valid legacy secret, preserving saved Telegram
links. The link-copy control intentionally contains this secret; the public
report-copy control includes only counters, port, route and mode.

## Build and verification

CI uses Java 17, Android SDK 36, NDK 28, Rust 1.88, and the locked npm/Rust
manifests. `npm run tauri -- android build --debug --apk --target aarch64 --ci`
bundles the frontend inside a signed APK; no development web server is required.
CI verifies the signature and the presence of each architecture's Rust library.
The x86_64 build is installed on an Android 15 emulator. The bounded smoke checks
Activity launch, process survival, and crash/ANR logs. When UIAutomator exposes
the WebView buttons, it also checks Start, five seconds in the background, Stop,
restart, and explicit force-stop/relaunch. It verifies the foreground service and
performs a real SOCKS5 greeting through ADB port forwarding to the Rust listener.
If buttons are inaccessible after a bounded wait, CI explicitly reports the
lifecycle checks as skipped; a launch-only pass is not lifecycle evidence.
`android-emulator-smoke-evidence` retains the exact result, UI dumps, service
state and logcat. This does not test automatic low-memory eviction, battery
behavior, Telegram connectivity, or a physical phone.

Checked-in `gen/android` contains the native source and Gradle wrapper. Tauri's
machine-specific generated glue, SDK paths, native build output and signing files
remain ignored. Run the same build command locally after installing Tauri's
[Android prerequisites](https://v2.tauri.app/start/prerequisites/#android).

No physical-phone or Telegram end-to-end test has been performed by this change.
Before promoting it beyond an experimental APK, test Android 13 notification
permission grant/denial, Android 14+ service startup, Start/Stop/restart, switching
to Telegram for at least 10 minutes, rotation, Activity recreation, process death,
Wi-Fi/mobile-data handover, and restoration with the same persisted secret.

Native bridging follows [Tauri mobile plugins](https://v2.tauri.app/develop/plugins/develop-mobile/)
and uses [Tauri opener](https://v2.tauri.app/plugin/opener/) for `tg://` links.
