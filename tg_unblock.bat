@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

:: ============================================================
::  TG Unblock — обход блокировки/замедления Telegram
::  Требуется запуск от имени администратора
:: ============================================================

:: --- Проверка прав администратора ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Скрипт требует прав администратора.
    echo     Перезапускаю с повышенными правами...
    powershell -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

set "SCRIPT_DIR=%~dp0"
set "TOOLS_DIR=%SCRIPT_DIR%tools"
set "GDPI_DIR=%TOOLS_DIR%\goodbyedpi-0.2.3rc3-2"
set "GDPI_EXE=%GDPI_DIR%\x86_64\goodbyedpi.exe"
set "BLACKLIST=%SCRIPT_DIR%tg_blacklist.txt"
set "GDPI_URL=https://github.com/ValdikSS/GoodbyeDPI/releases/download/0.2.3rc3/goodbyedpi-0.2.3rc3-2.zip"
set "GDPI_ZIP=%TOOLS_DIR%\goodbyedpi.zip"

title TG Unblock — Обход блокировки Telegram

:MENU
cls
echo ============================================================
echo           TG Unblock — Обход блокировки Telegram
echo ============================================================
echo.
echo   [*] ЗАПУСТИТЬ ОБХОД (авто) — нажмите 7
echo.
echo   [1] Сменить DNS (Cloudflare / Google)
echo   [2] Запустить GoodbyeDPI (обход DPI)
echo   [3] Комбинированный режим (DNS + GoodbyeDPI)
echo   [4] Тест соединения с Telegram
echo   [5] Сбросить настройки (вернуть DNS, остановить GoodbyeDPI)
echo   [6] Показать текущие настройки сети
echo   [7] === АВТО-ОБХОД (одна кнопка) ===
echo   [0] Выход
echo.
echo ============================================================
set /p "choice=Выберите действие [0-7]: "

if "%choice%"=="1" goto DNS_MENU
if "%choice%"=="2" goto DPI_START
if "%choice%"=="3" goto COMBINED
if "%choice%"=="4" goto TEST
if "%choice%"=="5" goto RESET
if "%choice%"=="6" goto SHOW_NET
if "%choice%"=="7" goto AUTO_BYPASS
if "%choice%"=="0" goto EXIT
echo [!] Неверный выбор.
timeout /t 2 >nul
goto MENU

:: ============================================================
::  1. СМЕНА DNS
:: ============================================================
:DNS_MENU
cls
echo ============================================================
echo                      Смена DNS
echo ============================================================
echo.
echo   [1] Cloudflare DNS  (1.1.1.1 / 1.0.0.1)
echo   [2] Google DNS       (8.8.8.8 / 8.8.4.4)
echo   [3] Quad9 DNS        (9.9.9.9 / 149.112.112.112)
echo   [4] Cloudflare DoH   (1.1.1.1 + DNS-over-HTTPS)
echo   [0] Назад
echo.
set /p "dns_choice=Выберите DNS провайдера [0-4]: "

if "%dns_choice%"=="1" (
    set "DNS1=1.1.1.1"
    set "DNS2=1.0.0.1"
    set "DNS_NAME=Cloudflare"
)
if "%dns_choice%"=="2" (
    set "DNS1=8.8.8.8"
    set "DNS2=8.8.4.4"
    set "DNS_NAME=Google"
)
if "%dns_choice%"=="3" (
    set "DNS1=9.9.9.9"
    set "DNS2=149.112.112.112"
    set "DNS_NAME=Quad9"
)
if "%dns_choice%"=="4" (
    set "DNS1=1.1.1.1"
    set "DNS2=1.0.0.1"
    set "DNS_NAME=Cloudflare DoH"
    goto SET_DNS_DOH
)
if "%dns_choice%"=="0" goto MENU

if not defined DNS1 (
    echo [!] Неверный выбор.
    timeout /t 2 >nul
    goto DNS_MENU
)

:SET_DNS
echo.
echo [*] Определяю активный сетевой адаптер...

for /f "tokens=1,2,3,4,*" %%a in ('netsh interface ipv4 show interfaces ^| findstr /i "connected"') do (
    set "ADAPTER_NAME=%%e"
)

if not defined ADAPTER_NAME (
    for /f "tokens=*" %%a in ('powershell -Command "(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1).Name"') do (
        set "ADAPTER_NAME=%%a"
    )
)

if not defined ADAPTER_NAME (
    echo [!] Не удалось определить сетевой адаптер.
    echo     Введите имя адаптера вручную (например: Ethernet, Wi-Fi):
    set /p "ADAPTER_NAME="
)

echo [*] Адаптер: !ADAPTER_NAME!
echo [*] Устанавливаю DNS: %DNS_NAME% (%DNS1%, %DNS2%)...

netsh interface ipv4 set dnsservers "!ADAPTER_NAME!" static %DNS1% primary validate=no >nul 2>&1
netsh interface ipv4 add dnsservers "!ADAPTER_NAME!" %DNS2% index=2 validate=no >nul 2>&1

echo [*] Очищаю DNS-кеш...
ipconfig /flushdns >nul 2>&1

echo.
echo [OK] DNS успешно изменён на %DNS_NAME% (%DNS1%, %DNS2%)
echo.
pause
goto MENU

:SET_DNS_DOH
echo.
echo [*] Определяю активный сетевой адаптер...

for /f "tokens=*" %%a in ('powershell -Command "(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1).Name"') do (
    set "ADAPTER_NAME=%%a"
)

if not defined ADAPTER_NAME (
    echo [!] Не удалось определить адаптер. Введите имя вручную:
    set /p "ADAPTER_NAME="
)

echo [*] Адаптер: !ADAPTER_NAME!
echo [*] Устанавливаю DNS: Cloudflare (1.1.1.1, 1.0.0.1)...

netsh interface ipv4 set dnsservers "!ADAPTER_NAME!" static 1.1.1.1 primary validate=no >nul 2>&1
netsh interface ipv4 add dnsservers "!ADAPTER_NAME!" 1.0.0.1 index=2 validate=no >nul 2>&1
ipconfig /flushdns >nul 2>&1

echo [*] Включаю DNS-over-HTTPS в системе (Windows 11+)...
powershell -Command "try { Set-DnsClientDohServerAddress -ServerAddress '1.1.1.1' -DohTemplate 'https://cloudflare-dns.com/dns-query' -AllowFallbackToUdp $true -AutoUpgrade $true -ErrorAction Stop; Set-DnsClientDohServerAddress -ServerAddress '1.0.0.1' -DohTemplate 'https://cloudflare-dns.com/dns-query' -AllowFallbackToUdp $true -AutoUpgrade $true -ErrorAction Stop; Write-Host '[OK] DoH активирован' } catch { Write-Host '[!] DoH недоступен на этой версии Windows, DNS установлен без DoH' }"

echo.
echo [OK] DNS установлен на Cloudflare с DoH.
echo.
pause
goto MENU

:: ============================================================
::  2. ЗАПУСК GoodbyeDPI
:: ============================================================
:DPI_START
cls
echo ============================================================
echo                  GoodbyeDPI — обход DPI
echo ============================================================
echo.

:: Проверяем наличие GoodbyeDPI
if not exist "%GDPI_EXE%" (
    echo [!] GoodbyeDPI не найден.
    goto DOWNLOAD_GDPI
)

:DPI_MODE_MENU
echo.
echo   Выберите режим GoodbyeDPI:
echo.
echo   [1] Режим -9  (максимальная защита, рекомендуется)
echo   [2] Режим -5  (средний)
echo   [3] Режим -1  (базовый, совместимый)
echo   [4] Кастомный  (-e 2 -f 2 -q -r -m)
echo   [5] Авто-перебор (попробует все режимы)
echo   [0] Назад
echo.
set /p "dpi_mode=Выберите режим [0-5]: "

if "%dpi_mode%"=="0" goto MENU

:: Убиваем старый процесс если запущен
taskkill /f /im goodbyedpi.exe >nul 2>&1
timeout /t 1 >nul

if "%dpi_mode%"=="1" (
    echo [*] Запускаю GoodbyeDPI в режиме -9 (максимальная защита)...
    start "" /B "%GDPI_EXE%" -9 --blacklist "%BLACKLIST%"
    goto DPI_STARTED
)
if "%dpi_mode%"=="2" (
    echo [*] Запускаю GoodbyeDPI в режиме -5 (средний)...
    start "" /B "%GDPI_EXE%" -5 --blacklist "%BLACKLIST%"
    goto DPI_STARTED
)
if "%dpi_mode%"=="3" (
    echo [*] Запускаю GoodbyeDPI в режиме -1 (базовый)...
    start "" /B "%GDPI_EXE%" -1 --blacklist "%BLACKLIST%"
    goto DPI_STARTED
)
if "%dpi_mode%"=="4" (
    echo [*] Запускаю GoodbyeDPI в кастомном режиме...
    start "" /B "%GDPI_EXE%" -e 2 -f 2 -q -r -m --blacklist "%BLACKLIST%"
    goto DPI_STARTED
)
if "%dpi_mode%"=="5" goto DPI_AUTO

echo [!] Неверный выбор.
timeout /t 2 >nul
goto DPI_MODE_MENU

:DPI_STARTED
timeout /t 2 >nul
tasklist /fi "imagename eq goodbyedpi.exe" 2>nul | findstr /i "goodbyedpi" >nul
if %errorlevel%==0 (
    echo.
    echo [OK] GoodbyeDPI запущен успешно!
    echo     Работает в фоне. Для остановки используйте пункт 5 (Сброс).
) else (
    echo.
    echo [!] GoodbyeDPI не удалось запустить.
    echo     Проверьте что антивирус не блокирует WinDivert.
)
echo.
pause
goto MENU

:: ============================================================
::  АВТО-ПЕРЕБОР РЕЖИМОВ
:: ============================================================
:DPI_AUTO
echo.
echo [*] Авто-перебор режимов GoodbyeDPI...
echo [*] Буду пробовать каждый режим и тестировать соединение.
echo.

set "MODES=-9;-5;-1;-e 2 -f 2 -q -r -m;-e 1 -f 1 -q -r -m -s;-p -f 2 -e 2 -q"
set "MODE_NAMES=Режим -9 (макс);Режим -5 (средний);Режим -1 (базовый);Кастом1 (-e2 -f2 -q -r -m);Кастом2 (-e1 -f1 -q -r -m -s);Кастом3 (-p -f2 -e2 -q)"
set "mode_idx=0"
set "best_mode="

for %%m in ("-9" "-5" "-1") do (
    set /a mode_idx+=1
    echo --- Тест !mode_idx!: GoodbyeDPI %%~m ---
    
    taskkill /f /im goodbyedpi.exe >nul 2>&1
    timeout /t 1 >nul
    
    start "" /B "%GDPI_EXE%" %%~m --blacklist "%BLACKLIST%"
    timeout /t 3 >nul
    
    tasklist /fi "imagename eq goodbyedpi.exe" 2>nul | findstr /i "goodbyedpi" >nul
    if !errorlevel! neq 0 (
        echo     [FAIL] Не запустился
    ) else (
        powershell -Command "$r = try { (Invoke-WebRequest -Uri 'https://web.telegram.org' -TimeoutSec 10 -UseBasicParsing).StatusCode } catch { 0 }; if ($r -eq 200) { Write-Host '    [OK] web.telegram.org доступен!'; exit 0 } else { Write-Host '    [FAIL] web.telegram.org недоступен'; exit 1 }"
        if !errorlevel!==0 (
            set "best_mode=%%~m"
            echo     [***] Рабочий режим найден: %%~m
        )
    )
)

:: Пробуем кастомные режимы
for %%p in (
    "-e 2 -f 2 -q -r -m"
    "-e 1 -f 1 -q -r -m -s"
    "-p -f 2 -e 2 -q"
) do (
    set /a mode_idx+=1
    echo --- Тест !mode_idx!: GoodbyeDPI %%~p ---
    
    taskkill /f /im goodbyedpi.exe >nul 2>&1
    timeout /t 1 >nul
    
    start "" /B "%GDPI_EXE%" %%~p --blacklist "%BLACKLIST%"
    timeout /t 3 >nul
    
    tasklist /fi "imagename eq goodbyedpi.exe" 2>nul | findstr /i "goodbyedpi" >nul
    if !errorlevel! neq 0 (
        echo     [FAIL] Не запустился
    ) else (
        powershell -Command "$r = try { (Invoke-WebRequest -Uri 'https://web.telegram.org' -TimeoutSec 10 -UseBasicParsing).StatusCode } catch { 0 }; if ($r -eq 200) { Write-Host '    [OK] web.telegram.org доступен!'; exit 0 } else { Write-Host '    [FAIL] web.telegram.org недоступен'; exit 1 }"
        if !errorlevel!==0 (
            if not defined best_mode (
                set "best_mode=%%~p"
                echo     [***] Рабочий режим найден: %%~p
            )
        )
    )
)

echo.
if defined best_mode (
    echo ============================================================
    echo [OK] Лучший рабочий режим: !best_mode!
    echo      Перезапускаю GoodbyeDPI с этим режимом...
    echo ============================================================
    taskkill /f /im goodbyedpi.exe >nul 2>&1
    timeout /t 1 >nul
    start "" /B "%GDPI_EXE%" !best_mode! --blacklist "%BLACKLIST%"
) else (
    echo ============================================================
    echo [!] Ни один режим GoodbyeDPI не помог.
    echo     Возможно, нужен VPN или MTProxy.
    echo ============================================================
    taskkill /f /im goodbyedpi.exe >nul 2>&1
)
echo.
pause
goto MENU

:: ============================================================
::  3. КОМБИНИРОВАННЫЙ РЕЖИМ
:: ============================================================
:COMBINED
cls
echo ============================================================
echo          Комбинированный режим (DNS + GoodbyeDPI)
echo ============================================================
echo.

:: --- DNS ---
echo [*] Устанавливаю DNS Cloudflare (1.1.1.1)...
for /f "tokens=*" %%a in ('powershell -Command "(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1).Name"') do (
    set "ADAPTER_NAME=%%a"
)
if defined ADAPTER_NAME (
    netsh interface ipv4 set dnsservers "!ADAPTER_NAME!" static 1.1.1.1 primary validate=no >nul 2>&1
    netsh interface ipv4 add dnsservers "!ADAPTER_NAME!" 1.0.0.1 index=2 validate=no >nul 2>&1
    ipconfig /flushdns >nul 2>&1
    echo [OK] DNS установлен: Cloudflare (1.1.1.1, 1.0.0.1)
) else (
    echo [!] Не удалось определить сетевой адаптер для DNS.
)

:: --- GoodbyeDPI ---
if not exist "%GDPI_EXE%" (
    echo.
    echo [!] GoodbyeDPI не найден. Скачиваю...
    call :DO_DOWNLOAD_GDPI
    if not exist "%GDPI_EXE%" (
        echo [!] Не удалось скачать GoodbyeDPI. Работаю только с DNS.
        pause
        goto MENU
    )
)

echo.
echo [*] Запускаю GoodbyeDPI в режиме -9...
taskkill /f /im goodbyedpi.exe >nul 2>&1
timeout /t 1 >nul
start "" /B "%GDPI_EXE%" -9 --blacklist "%BLACKLIST%"
timeout /t 2 >nul

tasklist /fi "imagename eq goodbyedpi.exe" 2>nul | findstr /i "goodbyedpi" >nul
if %errorlevel%==0 (
    echo [OK] GoodbyeDPI запущен.
) else (
    echo [!] GoodbyeDPI не запустился. Пробую режим -5...
    start "" /B "%GDPI_EXE%" -5 --blacklist "%BLACKLIST%"
    timeout /t 2 >nul
)

echo.
echo ============================================================
echo [OK] Комбинированный режим активирован:
echo      DNS: Cloudflare 1.1.1.1
echo      DPI: GoodbyeDPI
echo ============================================================
echo.

:: Быстрый тест
echo [*] Проверяю доступность Telegram...
powershell -Command "$r = try { $sw = [System.Diagnostics.Stopwatch]::StartNew(); $resp = Invoke-WebRequest -Uri 'https://web.telegram.org' -TimeoutSec 15 -UseBasicParsing; $sw.Stop(); Write-Host \"[OK] web.telegram.org доступен (${($sw.ElapsedMilliseconds)}ms)\"; } catch { Write-Host '[!] web.telegram.org пока недоступен, подождите немного...' }"
echo.
pause
goto MENU

:: ============================================================
::  4. ТЕСТ СОЕДИНЕНИЯ
:: ============================================================
:TEST
cls
echo ============================================================
echo           Тест соединения с Telegram
echo ============================================================
echo.

echo [*] Проверяю GoodbyeDPI...
tasklist /fi "imagename eq goodbyedpi.exe" 2>nul | findstr /i "goodbyedpi" >nul
if %errorlevel%==0 (
    echo     GoodbyeDPI: ЗАПУЩЕН
) else (
    echo     GoodbyeDPI: не запущен
)
echo.

echo [*] Текущий DNS:
powershell -Command "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses.Count -gt 0} | Format-Table InterfaceAlias, ServerAddresses -AutoSize"
echo.

echo [*] Пинг серверов Telegram (DC1-DC5)...
echo.

set "TG_IPS=149.154.175.50 149.154.167.51 149.154.175.100 149.154.167.91 91.108.56.100 91.108.4.100"

for %%i in (%TG_IPS%) do (
    echo     Пинг %%i...
    ping -n 1 -w 3000 %%i >nul 2>&1
    if !errorlevel!==0 (
        for /f "tokens=*" %%t in ('ping -n 1 -w 3000 %%i ^| findstr /i "time="') do (
            echo     [OK] %%i — %%t
        )
    ) else (
        echo     [FAIL] %%i — недоступен
    )
)

echo.
echo [*] Проверяю TCP-соединение (порт 443)...
echo.

for %%i in (149.154.175.50 149.154.167.51 91.108.56.100) do (
    powershell -Command "$tcp = New-Object System.Net.Sockets.TcpClient; try { $tcp.ConnectAsync('%%i', 443).Wait(5000) | Out-Null; if ($tcp.Connected) { Write-Host '    [OK] %%i:443 — TCP доступен' } else { Write-Host '    [FAIL] %%i:443 — таймаут' } } catch { Write-Host '    [FAIL] %%i:443 — отказано' } finally { $tcp.Dispose() }"
)

echo.
echo [*] Проверяю HTTPS доступность...
echo.

for %%u in (
    "https://web.telegram.org"
    "https://core.telegram.org"
    "https://t.me"
) do (
    powershell -Command "$url = '%%~u'; try { $sw = [System.Diagnostics.Stopwatch]::StartNew(); $r = Invoke-WebRequest -Uri $url -TimeoutSec 10 -UseBasicParsing; $sw.Stop(); $ms = $sw.ElapsedMilliseconds; Write-Host \"    [OK] $url — HTTP $($r.StatusCode) (${ms}ms)\" } catch { Write-Host \"    [FAIL] $url — недоступен\" }"
)

echo.
echo [*] Проверяю DNS резолвинг...
echo.

for %%d in (web.telegram.org core.telegram.org t.me telegram.org) do (
    powershell -Command "try { $ip = [System.Net.Dns]::GetHostAddresses('%%d') | Select-Object -First 1; Write-Host \"    [OK] %%d -> $($ip.IPAddressToString)\" } catch { Write-Host '    [FAIL] %%d — DNS не резолвится' }"
)

echo.
echo ============================================================
echo                    Тест завершён
echo ============================================================
echo.
pause
goto MENU

:: ============================================================
::  5. СБРОС НАСТРОЕК
:: ============================================================
:RESET
cls
echo ============================================================
echo                  Сброс настроек
echo ============================================================
echo.

echo [*] Останавливаю GoodbyeDPI...
taskkill /f /im goodbyedpi.exe >nul 2>&1
echo [OK] GoodbyeDPI остановлен.

echo.
echo [*] Возвращаю DNS к автоматическому (DHCP)...
for /f "tokens=*" %%a in ('powershell -Command "(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1).Name"') do (
    set "ADAPTER_NAME=%%a"
)
if defined ADAPTER_NAME (
    netsh interface ipv4 set dnsservers "!ADAPTER_NAME!" dhcp >nul 2>&1
    ipconfig /flushdns >nul 2>&1
    echo [OK] DNS сброшен на DHCP (автоматический).
) else (
    echo [!] Не удалось определить адаптер. Сбросьте DNS вручную.
)

echo.
echo [OK] Все настройки сброшены.
echo.
pause
goto MENU

:: ============================================================
::  6. ПОКАЗАТЬ ТЕКУЩИЕ НАСТРОЙКИ
:: ============================================================
:SHOW_NET
cls
echo ============================================================
echo              Текущие сетевые настройки
echo ============================================================
echo.

echo [*] Сетевые адаптеры:
powershell -Command "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Format-Table Name, InterfaceDescription, Status, LinkSpeed -AutoSize"

echo [*] DNS серверы:
powershell -Command "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses.Count -gt 0} | Format-Table InterfaceAlias, ServerAddresses -AutoSize"

echo [*] IP-конфигурация:
ipconfig | findstr /i "IPv4 Subnet Gateway DNS"

echo.
echo [*] GoodbyeDPI:
tasklist /fi "imagename eq goodbyedpi.exe" 2>nul | findstr /i "goodbyedpi" >nul
if %errorlevel%==0 (
    echo     Статус: ЗАПУЩЕН
    for /f "tokens=2" %%p in ('tasklist /fi "imagename eq goodbyedpi.exe" /fo list ^| findstr "PID"') do (
        echo     PID: %%p
    )
) else (
    echo     Статус: не запущен
)

echo.
pause
goto MENU

:: ============================================================
::  СКАЧИВАНИЕ GoodbyeDPI
:: ============================================================
:DOWNLOAD_GDPI
echo.
echo [*] GoodbyeDPI необходим для обхода DPI.
echo     Скачать автоматически с GitHub?
echo.
echo   [1] Да, скачать
echo   [0] Нет, назад
echo.
set /p "dl_choice=Выбор [0-1]: "
if "%dl_choice%"=="0" goto MENU
if "%dl_choice%"=="1" (
    call :DO_DOWNLOAD_GDPI
    if exist "%GDPI_EXE%" goto DPI_MODE_MENU
    pause
    goto MENU
)
goto MENU

:DO_DOWNLOAD_GDPI
echo.
echo [*] Создаю папку tools...
if not exist "%TOOLS_DIR%" mkdir "%TOOLS_DIR%"

echo [*] Скачиваю GoodbyeDPI с GitHub...
echo     URL: %GDPI_URL%
echo.

powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri '%GDPI_URL%' -OutFile '%GDPI_ZIP%' -UseBasicParsing; Write-Host '[OK] Скачано успешно' } catch { Write-Host \"[!] Ошибка скачивания: $($_.Exception.Message)\"; exit 1 }"

if not exist "%GDPI_ZIP%" (
    echo [!] Не удалось скачать файл.
    echo     Попробуйте скачать вручную:
    echo     %GDPI_URL%
    echo     и распаковать в %GDPI_DIR%
    exit /b 1
)

echo [*] Распаковываю...
powershell -Command "try { Expand-Archive -Path '%GDPI_ZIP%' -DestinationPath '%TOOLS_DIR%' -Force; Write-Host '[OK] Распаковано' } catch { Write-Host \"[!] Ошибка распаковки: $($_.Exception.Message)\"; exit 1 }"

:: Ищем goodbyedpi.exe рекурсивно
if not exist "%GDPI_EXE%" (
    echo [*] Ищу goodbyedpi.exe...
    for /f "tokens=*" %%f in ('powershell -Command "Get-ChildItem -Path '%TOOLS_DIR%' -Recurse -Filter 'goodbyedpi.exe' | Select-Object -First 1 | ForEach-Object { $_.DirectoryName }"') do (
        set "FOUND_DIR=%%f"
    )
    if defined FOUND_DIR (
        echo [*] Найден в: !FOUND_DIR!
        set "GDPI_DIR=!FOUND_DIR!"
        set "GDPI_EXE=!FOUND_DIR!\goodbyedpi.exe"
        
        :: Обновим путь для x86_64
        if not exist "!FOUND_DIR!\goodbyedpi.exe" (
            for /f "tokens=*" %%f in ('powershell -Command "Get-ChildItem -Path '%TOOLS_DIR%' -Recurse -Filter 'goodbyedpi.exe' | Select-Object -First 1 | ForEach-Object { $_.FullName }"') do (
                set "GDPI_EXE=%%f"
                echo [*] Путь к exe: %%f
            )
        )
    )
)

if exist "%GDPI_EXE%" (
    echo.
    echo [OK] GoodbyeDPI установлен: %GDPI_EXE%
    del "%GDPI_ZIP%" >nul 2>&1
) else (
    echo.
    echo [!] goodbyedpi.exe не найден после распаковки.
    echo     Проверьте папку: %TOOLS_DIR%
)
exit /b 0

:: ============================================================
::  7. АВТО-ОБХОД (одна кнопка) — замеряет ВСЕ режимы,
::     выбирает самый быстрый
:: ============================================================
:AUTO_BYPASS
cls
echo ============================================================
echo   АВТО-ОБХОД — тестирую ВСЕ режимы, выбираю лучший...
echo   Это займёт 2-3 минуты.
echo ============================================================
echo.

:: --- Шаг 1: Определяю адаптер ---
echo [1] Определяю сетевой адаптер...
set "ADAPTER_NAME="
for /f "tokens=*" %%a in ('powershell -Command "(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1).Name"') do (
    set "ADAPTER_NAME=%%a"
)
if not defined ADAPTER_NAME (
    echo [!] Не удалось определить адаптер.
    pause
    goto MENU
)
echo     Адаптер: !ADAPTER_NAME!

:: --- Шаг 2: DNS ---
echo.
echo [2] Устанавливаю DNS Cloudflare (1.1.1.1)...
netsh interface ipv4 set dnsservers "!ADAPTER_NAME!" static 1.1.1.1 primary validate=no >nul 2>&1
netsh interface ipv4 add dnsservers "!ADAPTER_NAME!" 1.0.0.1 index=2 validate=no >nul 2>&1
ipconfig /flushdns >nul 2>&1
echo     OK

:: --- Шаг 3: GoodbyeDPI ---
echo.
echo [3] Ищу GoodbyeDPI...
if not exist "%GDPI_EXE%" (
    echo     Не найден, скачиваю...
    call :DO_DOWNLOAD_GDPI
    if not exist "%GDPI_EXE%" (
        echo [!] Не удалось скачать GoodbyeDPI.
        pause
        goto MENU
    )
)
echo     OK: %GDPI_EXE%

:: --- Шаг 4: Бенчмарк каждого режима ---
echo.
echo ============================================================
echo   Замеряю скорость каждого режима...
echo ============================================================
echo.

set "BEST_MODE="
set "BEST_SCORE=99999"
set "BEST_LABEL="
set "MODE_NUM=0"

:: Benchmark function is a powershell one-liner that does
:: 2x TCP + 1x HTTPS, returns average ms (lower=better), 99999 if fail
set "BENCH_CMD=powershell -Command "$total=0; $ok=0; foreach($ip in @('149.154.167.51','149.154.175.50','91.108.56.100')) { foreach($i in 1..2) { $tcp=New-Object Net.Sockets.TcpClient; $sw=[Diagnostics.Stopwatch]::StartNew(); try { [void]$tcp.ConnectAsync($ip,443).Wait(4000); if($tcp.Connected){$sw.Stop();$total+=$sw.ElapsedMilliseconds;$ok++} } catch {} finally {$tcp.Dispose()} } }; try { $sw2=[Diagnostics.Stopwatch]::StartNew(); $r=Invoke-WebRequest 'https://web.telegram.org' -TimeoutSec 8 -UseBasicParsing; $sw2.Stop(); $total+=$sw2.ElapsedMilliseconds*3; $ok+=3 } catch {}; if($ok -eq 0){Write-Host 99999}else{Write-Host([math]::Floor($total/$ok))}""

:: Mode 1: без GoodbyeDPI (только DNS)
set /a MODE_NUM+=1
echo [%MODE_NUM%/8] Только DNS (без GoodbyeDPI)...
taskkill /f /im goodbyedpi.exe >nul 2>&1
timeout /t 1 >nul
for /f "tokens=*" %%s in ('%BENCH_CMD%') do set "SCORE=%%s"
echo     Скорость: !SCORE!ms
if !SCORE! LSS !BEST_SCORE! (
    set "BEST_SCORE=!SCORE!"
    set "BEST_MODE=dns_only"
    set "BEST_LABEL=Только DNS"
)

:: Mode 2: -9
set /a MODE_NUM+=1
echo [%MODE_NUM%/8] GoodbyeDPI -9 (максимальная защита)...
taskkill /f /im goodbyedpi.exe >nul 2>&1
timeout /t 1 >nul
start "" /B "%GDPI_EXE%" -9 --blacklist "%BLACKLIST%"
timeout /t 2 >nul
for /f "tokens=*" %%s in ('%BENCH_CMD%') do set "SCORE=%%s"
echo     Скорость: !SCORE!ms
if !SCORE! LSS !BEST_SCORE! (
    set "BEST_SCORE=!SCORE!"
    set "BEST_MODE=-9"
    set "BEST_LABEL=GoodbyeDPI -9"
)

:: Mode 3: -5
set /a MODE_NUM+=1
echo [%MODE_NUM%/8] GoodbyeDPI -5 (средний)...
taskkill /f /im goodbyedpi.exe >nul 2>&1
timeout /t 1 >nul
start "" /B "%GDPI_EXE%" -5 --blacklist "%BLACKLIST%"
timeout /t 2 >nul
for /f "tokens=*" %%s in ('%BENCH_CMD%') do set "SCORE=%%s"
echo     Скорость: !SCORE!ms
if !SCORE! LSS !BEST_SCORE! (
    set "BEST_SCORE=!SCORE!"
    set "BEST_MODE=-5"
    set "BEST_LABEL=GoodbyeDPI -5"
)

:: Mode 4: -1
set /a MODE_NUM+=1
echo [%MODE_NUM%/8] GoodbyeDPI -1 (базовый)...
taskkill /f /im goodbyedpi.exe >nul 2>&1
timeout /t 1 >nul
start "" /B "%GDPI_EXE%" -1 --blacklist "%BLACKLIST%"
timeout /t 2 >nul
for /f "tokens=*" %%s in ('%BENCH_CMD%') do set "SCORE=%%s"
echo     Скорость: !SCORE!ms
if !SCORE! LSS !BEST_SCORE! (
    set "BEST_SCORE=!SCORE!"
    set "BEST_MODE=-1"
    set "BEST_LABEL=GoodbyeDPI -1"
)

:: Mode 5: custom -e2 -f2 -q -r -m
set /a MODE_NUM+=1
echo [%MODE_NUM%/8] GoodbyeDPI -e2 -f2 -q -r -m...
taskkill /f /im goodbyedpi.exe >nul 2>&1
timeout /t 1 >nul
start "" /B "%GDPI_EXE%" -e 2 -f 2 -q -r -m --blacklist "%BLACKLIST%"
timeout /t 2 >nul
for /f "tokens=*" %%s in ('%BENCH_CMD%') do set "SCORE=%%s"
echo     Скорость: !SCORE!ms
if !SCORE! LSS !BEST_SCORE! (
    set "BEST_SCORE=!SCORE!"
    set "BEST_MODE=-e 2 -f 2 -q -r -m"
    set "BEST_LABEL=GoodbyeDPI -e2 -f2 -q -r -m"
)

:: Mode 6: custom -p -f2 -e2 -q
set /a MODE_NUM+=1
echo [%MODE_NUM%/8] GoodbyeDPI -p -f2 -e2 -q...
taskkill /f /im goodbyedpi.exe >nul 2>&1
timeout /t 1 >nul
start "" /B "%GDPI_EXE%" -p -f 2 -e 2 -q --blacklist "%BLACKLIST%"
timeout /t 2 >nul
for /f "tokens=*" %%s in ('%BENCH_CMD%') do set "SCORE=%%s"
echo     Скорость: !SCORE!ms
if !SCORE! LSS !BEST_SCORE! (
    set "BEST_SCORE=!SCORE!"
    set "BEST_MODE=-p -f 2 -e 2 -q"
    set "BEST_LABEL=GoodbyeDPI -p -f2 -e2 -q"
)

:: Mode 7: custom -e40 -f2 -q -r -m
set /a MODE_NUM+=1
echo [%MODE_NUM%/8] GoodbyeDPI -e40 -f2 -q -r -m...
taskkill /f /im goodbyedpi.exe >nul 2>&1
timeout /t 1 >nul
start "" /B "%GDPI_EXE%" -e 40 -f 2 -q -r -m --blacklist "%BLACKLIST%"
timeout /t 2 >nul
for /f "tokens=*" %%s in ('%BENCH_CMD%') do set "SCORE=%%s"
echo     Скорость: !SCORE!ms
if !SCORE! LSS !BEST_SCORE! (
    set "BEST_SCORE=!SCORE!"
    set "BEST_MODE=-e 40 -f 2 -q -r -m"
    set "BEST_LABEL=GoodbyeDPI -e40 -f2 -q -r -m"
)

:: Mode 8: -9 --set-ttl 5
set /a MODE_NUM+=1
echo [%MODE_NUM%/8] GoodbyeDPI -9 --set-ttl 5...
taskkill /f /im goodbyedpi.exe >nul 2>&1
timeout /t 1 >nul
start "" /B "%GDPI_EXE%" -9 --set-ttl 5 --blacklist "%BLACKLIST%"
timeout /t 2 >nul
for /f "tokens=*" %%s in ('%BENCH_CMD%') do set "SCORE=%%s"
echo     Скорость: !SCORE!ms
if !SCORE! LSS !BEST_SCORE! (
    set "BEST_SCORE=!SCORE!"
    set "BEST_MODE=-9 --set-ttl 5"
    set "BEST_LABEL=GoodbyeDPI -9 --set-ttl 5"
)

:: --- Применяем лучший ---
echo.
echo ============================================================

if "!BEST_SCORE!"=="99999" (
    echo [!] Ни один режим не сработал. Попробуйте VPN или MTProxy.
    taskkill /f /im goodbyedpi.exe >nul 2>&1
    pause
    goto MENU
)

echo   ЛУЧШИЙ РЕЖИМ: !BEST_LABEL!
echo   СКОРОСТЬ:     !BEST_SCORE!ms
echo ============================================================
echo.

taskkill /f /im goodbyedpi.exe >nul 2>&1
timeout /t 1 >nul

if "!BEST_MODE!"=="dns_only" (
    echo [OK] DNS Cloudflare достаточно, GoodbyeDPI не нужен.
) else (
    echo [*] Запускаю GoodbyeDPI с лучшими параметрами...
    start "" /B "%GDPI_EXE%" !BEST_MODE! --blacklist "%BLACKLIST%"
    timeout /t 2 >nul
    echo [OK] GoodbyeDPI запущен: !BEST_MODE!
)

echo.
echo ============================================================
echo [OK] ОБХОД АКТИВИРОВАН!
echo     DNS: Cloudflare 1.1.1.1
echo     Режим: !BEST_LABEL! (!BEST_SCORE!ms)
echo     Для остановки — пункт 5 в меню.
echo ============================================================
pause
goto MENU

:: ============================================================
::  ВЫХОД
:: ============================================================
:EXIT
echo.
echo [*] GoodbyeDPI будет остановлен при выходе? (y/n)
set /p "exit_choice="
if /i "%exit_choice%"=="y" (
    taskkill /f /im goodbyedpi.exe >nul 2>&1
    echo [OK] GoodbyeDPI остановлен.
)
echo.
echo Bye!
endlocal
exit /b 0
