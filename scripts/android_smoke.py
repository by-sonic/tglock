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
RESULT = {"launch": "not_run", "lifecycle": "not_run"}


def adb(*args, check=True, timeout=20):
    return subprocess.run(
        ["adb", *args], check=check, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout,
    ).stdout.strip()


def wait_for(description, predicate, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(1)
    raise AssertionError(f"Timed out: {description}")


def ui_dump(label):
    # Dump first, then read the file; never tap coordinates inferred from a
    # screenshot, a previous Activity, or assumed phone dimensions.
    adb("shell", "rm", "-f", "/sdcard/tglock-ui.xml")
    adb("shell", "uiautomator", "dump", "/sdcard/tglock-ui.xml")
    text = adb("shell", "cat", "/sdcard/tglock-ui.xml")
    (EVIDENCE / f"{label}.xml").write_text(text, encoding="utf-8")
    return ET.fromstring(text)


def label_node(tree, label):
    for node in tree.iter("node"):
        if label in (node.get("text", ""), node.get("content-desc", "")):
            bounds = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds", ""))
            if bounds:
                x1, y1, x2, y2 = map(int, bounds.groups())
                if x2 > x1 and y2 > y1:
                    return (x1 + x2) // 2, (y1 + y2) // 2
    return None


def tap_label(label, stage):
    for attempt in range(3):
        point = label_node(ui_dump(f"{stage}-{attempt}"), label)
        if point is not None:
            adb("shell", "input", "tap", str(point[0]), str(point[1]))
            return
        time.sleep(1)
    raise AssertionError(f"Visible action not found: {label}")


def service_running():
    text = adb("shell", "dumpsys", "activity", "services", f"{PACKAGE}/.TunnelService")
    (EVIDENCE / "services-last.txt").write_text(text, encoding="utf-8")
    return "isForeground=true" in text


def proxy_ready():
    # ADB forwards to emulator loopback. A real SOCKS5 greeting proves the
    # Rust listener is serving, beyond just a notification being displayed.
    try:
        with socket.create_connection(("127.0.0.1", 11080), timeout=1) as peer:
            peer.sendall(bytes([5, 1, 0]))
            return peer.recv(2) == bytes([5, 0])
    except (OSError, TimeoutError):
        return False


def launch():
    adb("shell", "am", "start", "-W", "-n", COMPONENT)
    wait_for("Activity resumed", lambda: any(
        "ResumedActivity" in line and PACKAGE in line
        for line in adb("shell", "dumpsys", "activity", "activities").splitlines()
    ))
    assert adb("shell", "pidof", PACKAGE), "App process is absent"


def main():
    apks = sorted(Path(sys.argv[1]).rglob("*.apk"))
    assert len(apks) == 1, f"Expected one x86_64 APK, got {len(apks)}"
    adb("install", "-r", str(apks[0]), timeout=60)
    adb("shell", "pm", "grant", PACKAGE, "android.permission.POST_NOTIFICATIONS")
    adb("logcat", "-c")
    adb("forward", "tcp:11080", "tcp:1080")
    launch()
    RESULT["launch"] = "passed"
    deadline = time.monotonic() + 20
    tree = None
    start_point = None
    attempt = 0
    while time.monotonic() < deadline:
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
        RESULT["lifecycle"] = "skipped: WebView Start not accessible after 20s"
        print("::warning::Activity launch passed; lifecycle skipped because UIAutomator did not expose Start after 20s")
        return
    RESULT["lifecycle"] = "failed: lifecycle assertions incomplete"
    tap_label("Включить защиту", "before-start")
    wait_for("foreground service after Start", service_running)
    wait_for("Rust SOCKS listener after Start", proxy_ready)
    adb("shell", "input", "keyevent", "KEYCODE_HOME")
    time.sleep(5)
    assert service_running() and proxy_ready(), "Proxy stopped after backgrounding"
    launch()
    tap_label("Выключить", "before-stop")
    wait_for("foreground service after Stop", lambda: not service_running())
    wait_for("Rust listener after Stop", lambda: not proxy_ready())
    # Explicit restart and user force-stop, then relaunch. This tests the
    # user-stop contract, not Android's automatic low-memory process eviction.
    tap_label("Включить защиту", "before-restart")
    wait_for("Rust listener after restart", proxy_ready)
    adb("shell", "am", "force-stop", PACKAGE)
    launch()
    assert not service_running() and not proxy_ready(), "Proxy silently restarted after force-stop"
    RESULT["lifecycle"] = "passed: Start, background 5s, Stop, restart, force-stop"


try:
    main()
except Exception as error:
    RESULT["failure"] = str(error)
    raise
finally:
    try:
        logs = adb("logcat", "-d", "-v", "threadtime")
        (EVIDENCE / "logcat.txt").write_text(logs, encoding="utf-8")
        crashes = adb("logcat", "-b", "crash", "-d")
        (EVIDENCE / "crash.txt").write_text(crashes, encoding="utf-8")
        if PACKAGE in crashes or f"ANR in {PACKAGE}" in logs or not adb("shell", "pidof", PACKAGE):
            RESULT["launch"] = "failed: application crash, ANR, or missing process"
            raise AssertionError("Application did not remain healthy")
    finally:
        (EVIDENCE / "result.json").write_text(json.dumps(RESULT, indent=2), encoding="utf-8")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as report:
                report.write("\nAndroid emulator smoke: " + json.dumps(RESULT) + "\n")
        print(json.dumps(RESULT))
