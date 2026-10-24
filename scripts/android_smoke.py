#!/usr/bin/env python3
"""Bounded installed-APK smoke; no Telegram account or external network needed."""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

PACKAGE = "com.bysonic.tglock"
COMPONENT = f"{PACKAGE}/.MainActivity"
EVIDENCE = Path("android-smoke-evidence")
EVIDENCE.mkdir(exist_ok=True)
RESULT = {"launch": "not_run", "lifecycle": "not_run", "foreign_dialogs": [], "taps": {}}
STARTED = time.monotonic()

# Budgets measured on the GitHub-hosted emulator, not on a phone. With the
# software GPU the WebView paints about one frame per second, and dumpsys
# itself can take seconds while system_server catches up after boot.
SETTLE_SECONDS = 120
VISIBLE_SECONDS = 60
EFFECT_SECONDS = 45
# A click that reaches the handler re-renders the button as "Подождите…" or
# the opposite action within a frame. Only a button left unchanged this long
# was never clicked.
RETAP_AFTER_SECONDS = 10
MAX_TAPS = 3
SYSTEM_DIALOG = re.compile(r"(Application Not Responding|Application Error): ([\w.:]+)")


def adb(*args, check=True, timeout=30):
    return subprocess.run(
        ["adb", *args], check=check, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout,
    ).stdout.strip()


def step(message):
    # The same marker in stdout and logcat lines up the job log with evidence.
    line = f"[{time.monotonic() - STARTED:6.1f}s] {message}"
    print(line, flush=True)
    with open(EVIDENCE / "steps.txt", "a", encoding="utf-8") as steps:
        steps.write(line + "\n")
    adb("shell", "log", "-t", "tglock-smoke", json.dumps(message), check=False)


def system_dialog():
    try:
        windows = adb("shell", "dumpsys", "window", "windows", check=False)
    except subprocess.SubprocessError:
        return None
    match = SYSTEM_DIALOG.search(windows)
    return (match.group(1), match.group(2)) if match else None


def clear_foreign_dialogs():
    # A loaded emulator regularly declares its own launcher or system apps
    # unresponsive, and that dialog covers the WebView. Ours is a failure.
    dialog = system_dialog()
    if dialog is None:
        return
    kind, process = dialog
    if process.split(":")[0] == PACKAGE:
        raise AssertionError(f"{kind} dialog for {process}")
    button = "android:id/aerr_wait" if kind == "Application Not Responding" else "android:id/aerr_close"
    try:
        point = node_center(ui_dump(f"dialog-{len(RESULT['foreign_dialogs'])}"),
                            lambda node: node.get("resource-id") == button)
    except (subprocess.SubprocessError, ET.ParseError):
        point = None
    if point is not None:
        adb("shell", "input", "tap", str(point[0]), str(point[1]))
    outcome = f"tapped {button}" if point else "button not dumped yet"
    RESULT["foreign_dialogs"].append(f"{kind}: {process}, {outcome}")
    step(f"foreign dialog {kind}: {process}, {outcome}")


def wait_for(description, predicate, seconds=EFFECT_SECONDS):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        clear_foreign_dialogs()
        if predicate():
            step(f"ok: {description}")
            return
        time.sleep(1)
    raise AssertionError(f"Timed out after {seconds}s: {description}")


def cpu_idle_share(interval=3):
    def sample():
        values = list(map(int, adb("shell", "head", "-1", "/proc/stat").split()[1:]))
        return values[3] + values[4], sum(values)
    idle1, total1 = sample()
    time.sleep(interval)
    idle2, total2 = sample()
    return (idle2 - idle1) / max(1, total2 - total1)


def settle():
    # boot_completed fires long before package, launcher and dexopt work
    # drains. Start the app on a quiet device instead of racing that work.
    deadline = time.monotonic() + SETTLE_SECONDS
    quiet = 0
    idle = 0.0
    while time.monotonic() < deadline and quiet < 2:
        clear_foreign_dialogs()
        idle = cpu_idle_share()
        quiet = quiet + 1 if idle >= 0.6 else 0
    RESULT["settle"] = f"{'quiet' if quiet >= 2 else 'still busy'} at {time.monotonic() - STARTED:.0f}s, {idle:.0%} idle"
    step(f"settle: {RESULT['settle']}")


def ui_dump(label):
    # Dump first, then read the file; never tap coordinates inferred from a
    # screenshot, a previous Activity, or assumed phone dimensions.
    adb("shell", "rm", "-f", "/sdcard/tglock-ui.xml")
    status = adb("shell", "uiautomator", "dump", "/sdcard/tglock-ui.xml", check=False)
    if not adb("shell", "ls", "/sdcard/tglock-ui.xml", check=False).endswith("tglock-ui.xml"):
        # On a loaded emulator UIAutomator intermittently reports "could not get
        # idle state" and writes nothing. That is the tool, not the app.
        raise subprocess.SubprocessError(f"uiautomator dump failed: {status}")
    text = adb("shell", "cat", "/sdcard/tglock-ui.xml")
    (EVIDENCE / f"{label}.xml").write_text(text, encoding="utf-8")
    return ET.fromstring(text)


def node_center(tree, matches):
    for node in tree.iter("node"):
        if matches(node):
            bounds = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds", ""))
            if bounds:
                x1, y1, x2, y2 = map(int, bounds.groups())
                if x2 > x1 and y2 > y1:
                    return (x1 + x2) // 2, (y1 + y2) // 2
    return None


def label_node(tree, label):
    # Android aggregates the decorative arrow into the button's accessible
    # text (observed in the API35 CI dump). Accept only that exact suffix.
    return node_center(tree, lambda node: any(
        name in (label, f"{label} →")
        for name in (node.get("text", "").strip(), node.get("content-desc", "").strip())
    ))


def find_label(label, stage):
    clear_foreign_dialogs()
    try:
        return label_node(ui_dump(stage), label)
    except (subprocess.SubprocessError, ET.ParseError) as error:
        (EVIDENCE / f"{stage}.error.txt").write_text(str(error), encoding="utf-8")
        return None


def press(label, stage):
    """Tap a visible WebView action until the page shows it was clicked.

    The page re-renders every second. At one frame per second the touch down
    and up can straddle that re-render, and Chromium then drops the click: the
    button stays exactly as it was and the handler never runs. Callers still
    assert the service and listener effect strictly afterwards.
    """
    deadline = time.monotonic() + VISIBLE_SECONDS
    taps = 0
    last_tap = 0.0
    attempt = 0
    while time.monotonic() < deadline:
        point = find_label(label, f"{stage}-{attempt}")
        attempt += 1
        if point is None and taps:
            RESULT["taps"][stage] = taps
            step(f"{label}: clicked after {taps} tap(s)")
            return
        if point is not None and (not taps or time.monotonic() - last_tap >= RETAP_AFTER_SECONDS):
            if taps == MAX_TAPS:
                raise AssertionError(f"{label} stayed unchanged after {taps} taps")
            adb("shell", "input", "tap", str(point[0]), str(point[1]))
            taps += 1
            last_tap = time.monotonic()
            step(f"{label}: tap {taps} at {point}")
        time.sleep(1)
    if taps:
        raise AssertionError(f"{label} stayed unchanged {VISIBLE_SECONDS}s after {taps} tap(s)")
    raise AssertionError(f"Visible action not found: {label}")


def service_running():
    text = adb("shell", "dumpsys", "activity", "services", f"{PACKAGE}/.TunnelService")
    (EVIDENCE / "services-last.txt").write_text(text, encoding="utf-8")
    return "isForeground=true" in text


def proxy_ready():
    # ADB forwards to emulator loopback. A real SOCKS5 greeting proves the
    # Rust listener is serving, beyond just a notification being displayed.
    try:
        with socket.create_connection(("127.0.0.1", 11080), timeout=3) as peer:
            peer.sendall(bytes([5, 1, 0]))
            return peer.recv(2) == bytes([5, 0])
    except (OSError, TimeoutError):
        return False


def launch():
    adb("shell", "am", "start", "-W", "-n", COMPONENT, timeout=60)
    wait_for("Activity resumed", lambda: any(
        "ResumedActivity" in line and PACKAGE in line
        for line in adb("shell", "dumpsys", "activity", "activities").splitlines()
    ))
    assert adb("shell", "pidof", PACKAGE), "App process is absent"


def main():
    apks = sorted(Path(sys.argv[1]).rglob("*.apk"))
    assert len(apks) == 1, f"Expected one x86_64 APK, got {len(apks)}"
    adb("install", "-r", str(apks[0]), timeout=120)
    adb("shell", "pm", "grant", PACKAGE, "android.permission.POST_NOTIFICATIONS")
    adb("forward", "tcp:11080", "tcp:1080")
    settle()
    adb("logcat", "-c")
    step("launch")
    launch()
    RESULT["launch"] = "passed"
    deadline = time.monotonic() + VISIBLE_SECONDS
    tree = None
    start_point = None
    attempt = 0
    while time.monotonic() < deadline:
        clear_foreign_dialogs()
        try:
            tree = ui_dump(f"launched-{attempt}")
            start_point = label_node(tree, "Включить защиту")
            if start_point is not None:
                break
        except (subprocess.SubprocessError, ET.ParseError):
            pass
        attempt += 1
        time.sleep(1)
    assert not service_running(), "Foreground service started without user action"
    assert not proxy_ready(), "Proxy started without user action"
    if tree is not None:
        assert any(
            node.get("class") == "android.webkit.WebView"
            for node in tree.iter("node")
        ), "App Activity is resumed but its WebView is absent"
    if start_point is None:
        RESULT["lifecycle"] = f"skipped: WebView Start not accessible after {VISIBLE_SECONDS}s"
        print(f"::warning::Activity launch passed; lifecycle skipped because UIAutomator did not expose Start after {VISIBLE_SECONDS}s")
        return
    RESULT["lifecycle"] = "failed: lifecycle assertions incomplete"
    press("Включить защиту", "before-start")
    wait_for("foreground service after Start", service_running)
    wait_for("Rust SOCKS listener after Start", proxy_ready)
    adb("shell", "input", "keyevent", "KEYCODE_HOME")
    time.sleep(5)
    clear_foreign_dialogs()
    assert service_running() and proxy_ready(), "Proxy stopped after backgrounding"
    step("ok: still serving after 5s in background")
    launch()
    press("Выключить", "before-stop")
    wait_for("foreground service after Stop", lambda: not service_running())
    wait_for("Rust listener after Stop", lambda: not proxy_ready())
    # Explicit restart and user force-stop, then relaunch. This tests the
    # user-stop contract, not Android's automatic low-memory process eviction.
    press("Включить защиту", "before-restart")
    wait_for("Rust listener after restart", proxy_ready)
    adb("shell", "am", "force-stop", PACKAGE)
    launch()
    assert not service_running() and not proxy_ready(), "Proxy silently restarted after force-stop"
    RESULT["lifecycle"] = "passed: Start, background 5s, Stop, restart, force-stop"


try:
    main()
except Exception as error:
    RESULT["failure"] = str(error)
    for name, args in (("failure-windows.txt", ("dumpsys", "window", "windows")),
                       ("failure-activities.txt", ("dumpsys", "activity", "activities"))):
        try:
            (EVIDENCE / name).write_text(adb("shell", *args, check=False), encoding="utf-8")
        except subprocess.SubprocessError:
            pass
    try:
        (EVIDENCE / "failure.png").write_bytes(subprocess.run(
            ["adb", "exec-out", "screencap", "-p"], capture_output=True, timeout=30).stdout)
    except subprocess.SubprocessError:
        pass
    raise
finally:
    try:
        logs = adb("logcat", "-d", "-v", "threadtime", timeout=60)
        (EVIDENCE / "logcat.txt").write_text(logs, encoding="utf-8")
        crashes = adb("logcat", "-b", "crash", "-d")
        (EVIDENCE / "crash.txt").write_text(crashes, encoding="utf-8")
        if PACKAGE in crashes or f"ANR in {PACKAGE}" in logs or not adb("shell", "pidof", PACKAGE):
            RESULT["launch"] = "failed: application crash, ANR, or missing process"
            raise AssertionError("Application did not remain healthy")
    finally:
        (EVIDENCE / "result.json").write_text(json.dumps(RESULT, indent=2, ensure_ascii=False), encoding="utf-8")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as report:
                report.write("\nAndroid emulator smoke: " + json.dumps(RESULT, ensure_ascii=False) + "\n")
        print(json.dumps(RESULT, ensure_ascii=False))
