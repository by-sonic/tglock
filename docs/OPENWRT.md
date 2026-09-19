# CLI для ARM64 / OpenWrt

Цель сборки — `aarch64-unknown-linux-musl`: ARM64 Linux, статический бинарь без
зависимости от glibc, OpenSSL или WebView. Это подходит для 64-битной прошивки
NanoPi R4S и других ARM64-роутеров. MIPS и 32-битный ARM требуют другой сборки.
Проверьте архитектуру прошивки командой `uname -m`: ожидается `aarch64`.

Workflow **Static ARM64 CLI** собирает и запускает тесты на ARM64 runner,
проверяет ELF (нет `INTERP` и `NEEDED`), запуск CLI, завершение по SIGTERM и
сохранение секрета между запусками. Артефакт содержит бинарь и SHA-256.
Release workflow прикладывает такой же проверенный артефакт к будущим релизам.
Наличие сборки в PR не означает, что уже опубликован новый релиз.

Это проверка ARM64 Linux, а не испытание конкретной прошивки OpenWrt или
доступности Telegram через вашего провайдера.

## Установка

Скачайте артефакт успешного запуска workflow нужного PR либо файл
`tglock-cli-aarch64-unknown-linux-musl` из релиза, если он там опубликован.
Сверьте SHA-256, скопируйте бинарь на роутер и выполните:

```sh
chmod 755 /usr/bin/tglock-cli
/usr/bin/tglock-cli --version
mkdir -p /etc/tglock
chmod 700 /etc/tglock
```

Создайте `/etc/tglock/tglock.toml`:

```toml
port = 1080
lan = true
secret_file = "/etc/tglock/secret"
# worker = ["your-name.workers.dev"]
```

`lan = true` нужен для телефонов и компьютеров в домашней сети. По умолчанию
CLI слушает только loopback. Секрет создаётся при первом запуске и сохраняется
в указанном файле; он не должен теряться при перезагрузке или обновлении.

```sh
chmod 600 /etc/tglock/tglock.toml
/usr/bin/tglock-cli --config /etc/tglock/tglock.toml
```

В Telegram выберите MTProto и используйте LAN-адрес роутера, порт `1080` и
секрет из напечатанной ссылки. `127.0.0.1` на телефоне означает сам телефон.
Разрешайте входящий TCP `1080` только из доверенной LAN; не публикуйте порт
в WAN. Звонки через UDP эта сборка не реализует.

## Сервис procd

После проверки ручного запуска сохраните `/etc/init.d/tglock`:

```sh
#!/bin/sh /etc/rc.common
START=95
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/tglock-cli --config /etc/tglock/tglock.toml
    procd_set_param respawn 3600 5 5
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
```

```sh
chmod 755 /etc/init.d/tglock
/etc/init.d/tglock enable
/etc/init.d/tglock start
logread -e tglock
```

Обновление: остановите сервис, замените бинарь после проверки контрольной суммы,
сохраните `/etc/tglock`, запустите сервис снова. Для отмены автозапуска используйте
`/etc/init.d/tglock stop` и `/etc/init.d/tglock disable`.

## TLS и маршруты

Встроенный набор доверенных корневых сертификатов webpki обновляется вместе с
бинарём. Проверка сертификата и имени включена: при подключении к закреплённому
IP имя Telegram по-прежнему используется для SNI и проверки сертификата.
На роутере должно быть установлено правильное время.

Если все Telegram IP недоступны, нужен доступный маршрут через собственный
[Cloudflare Worker](CLOUDFLARE_WORKER.md). Статическая сборка сама по себе не
устраняет блокировку всех внешних маршрутов.
