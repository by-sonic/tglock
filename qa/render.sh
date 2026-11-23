#!/usr/bin/env bash
set -euo pipefail
export DISPLAY=:90 XDG_SESSION_TYPE=x11 XDG_CURRENT_DESKTOP=XFCE
export XDG_RUNTIME_DIR=/tmp/xdg-qa
mkdir -m 700 -p "$XDG_RUNTIME_DIR"
Xvfb "$DISPLAY" -screen 0 1024x768x24 -nolisten tcp +extension GLX & xp=$!
trap 'kill "$xp" 2>/dev/null || true' EXIT
for i in {1..50}; do xdpyinfo >/dev/null 2>&1 && break; sleep .2; done
xfwm4 --compositor=off >/tmp/xfwm.log 2>&1 &
cat /etc/os-release | tee /evidence/os.txt
pacman -Q mesa xfwm4 gtk3 webkit2gtk-4.1 | tee /evidence/versions.txt
glxinfo -B | tee /evidence/glx.txt
for n in 15 21 22; do
  dir="/home/qa/v$n"; mkdir -p "$dir"; cd "$dir"
  install -m755 "/images/TGLock_2.0.0-beta.${n}_amd64.AppImage" ./app
  ./app --appimage-extract > /dev/null
  export XDG_CONFIG_HOME="$dir/config" XDG_DATA_HOME="$dir/data" XDG_CACHE_HOME="$dir/cache"
  mkdir -p "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME"
  ./squashfs-root/AppRun >"/evidence/v$n.log" 2>&1 & pid=$!
  window=""
  for i in {1..50}; do
    window=$(xdotool search --onlyvisible --name '^TGLock$' 2>/dev/null | tail -1 || true)
    [[ -n "$window" ]] && break
    kill -0 "$pid" 2>/dev/null || break
    sleep .5
  done
  outcome=no-window
  if [[ -n "$window" ]]; then
    for delay in 3 5 8; do
      sleep "$delay"
      if ! magick import -window "$window" "/evidence/v$n.png" 2>/dev/null; then break; fi
      tesseract "/evidence/v$n.png" "/evidence/v$n" -l rus+eng --psm 6 2>/dev/null || true
      if grep -Eiq 'защит|Telegram|диагностик' "/evidence/v$n.txt"; then outcome=rendered; break; fi
      outcome=blank-or-unrecognized
    done
  fi
  echo "$outcome" | tee "/evidence/v$n.result"
  echo "beta.$n = $outcome"
  grep -iE 'EGL|Aborting|error|Failed|cannot|not found|Operation not permitted' "/evidence/v$n.log" | head -10 || true
  if [[ -f "/evidence/v$n.txt" ]]; then cat "/evidence/v$n.txt"; fi
  kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
done
test "$(cat /evidence/v22.result)" = rendered
