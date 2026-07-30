#!/usr/bin/env python3
"""Проверяет, что в бандл приложения попал GUI-бинарь, а не headless CLI.

Зачем это существует. В v2.0.0-beta.2 и v2.0.0-beta.3 бандлер Tauri упаковал
`tglock-cli` как исполняемый файл приложения, и оно не запускалось ни на одной
платформе. В beta.3 имя файла было уже правильным — бандлер переименовал CLI —
поэтому проверка имени или `CFBundleExecutable` ничего не заметила. Отличить
можно только по содержимому.

Почему на Python, а не grep. BSD grep на macOS в UTF-8-локали молча не находит
строки в бинарных данных там, где GNU grep находит: проверка проходила на
Linux и давала ложное «не GUI» на macOS. Один скрипт для всех платформ и для
всех трёх мест, где проверка вызывается, исключает подобные расхождения.

Использование:
    python3 scripts/verify_bundle_binary.py <путь-к-бинарю>
"""

import sys

# Присутствуют только в GUI: строка CSP из tauri.conf.json и имя движка WebView.
GUI_MARKERS = (b"ipc.localhost", b"wry")
# Присутствуют только в CLI: имена флагов clap.
CLI_MARKERS = (b"allow-direct", b"secret-file")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"использование: {argv[0]} <путь-к-бинарю>", file=sys.stderr)
        return 2

    path = argv[1]
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as error:
        print(f"не удалось прочитать {path}: {error}", file=sys.stderr)
        return 1

    found_gui = [marker.decode() for marker in GUI_MARKERS if marker in data]
    found_cli = [marker.decode() for marker in CLI_MARKERS if marker in data]

    print(f"файл:     {path}")
    print(f"размер:   {len(data) / 1048576:.1f} МБ")
    print(f"GUI:      {found_gui or 'признаков нет'}")
    print(f"CLI:      {found_cli or 'признаков нет'}")

    if found_cli:
        print("ОШИБКА: в бандле headless CLI вместо приложения", file=sys.stderr)
        return 1
    if not found_gui:
        print("ОШИБКА: это не GUI-бинарь, признаков GUI нет", file=sys.stderr)
        return 1

    print("OK: в бандле GUI-бинарь")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
