# Свой домен на Cloudflare (CF-прокси)

Ещё один резервный маршрут на случай, когда провайдер режет все обычные адреса
Telegram. В отличие от [Cloudflare Worker](CLOUDFLARE_WORKER.md) здесь нет
скрипта и лимитов Worker'ов: Cloudflare сам проксирует WebSocket до Telegram
по DNS-записям вашего домена. Нужен только домен (подойдёт любой, обычно это
150–300 ₽ в год).

Схема та же, что у CF-прокси в [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy/blob/main/docs/RU/CfProxy.md)
(идея — [Nekogram/WSProxy](https://github.com/Nekogram/WSProxy)):

```
Telegram → TGLock → wss://kws2.ваш-домен/apiws → Cloudflare → 149.154.167.51 (DC2)
```

## Настройка

1. Добавьте домен в Cloudflare: купите его там или смените NS-серверы у
   регистратора ([инструкция Cloudflare](https://developers.cloudflare.com/dns/zone-setups/full-setup/setup/)).
2. **SSL/TLS → Overview** — режим **Flexible**. До Cloudflare соединение
   остаётся HTTPS с проверкой сертификата, а от Cloudflare до Telegram идёт по
   порту 80: у адресов Telegram нет сертификата на ваш домен.
3. **DNS → Records** — `A`-записи с включённым проксированием (оранжевое облако):

   | Name | IPv4 |
   |---|---|
   | `kws1` | `149.154.175.50` |
   | `kws2` | `149.154.167.51` |
   | `kws3` | `149.154.175.100` |
   | `kws4` | `149.154.167.91` |
   | `kws5` | `149.154.171.5` |
   | `kws203` | `91.105.192.100` |

4. Укажите в TGLock **только домен**, без `kws` и без `https://`:
   - в приложении: **Настройки → Свой домен на Cloudflare** → `example.com`;
   - в CLI: `tglock-cli --cf-proxy example.com` или `cf_proxy = ["example.com"]` в `tglock.toml`.

   В журнале появится строка `CF-прокси в списке маршрутов: kws1.example.com …`.
   Если строка начинается с «не похож на имя домена» — домен вписан со схемой
   или со слэшем.

## Что учесть

- Если у провайдера заблокирована сама сеть Cloudflare, этот маршрут не
  поможет, как и Worker.
- Маршрут участвует в общем переборе вместе с Worker'ом: его проверка
  начинается сразу после основного адреса Telegram, успешный запоминается.
- Шифрование Telegram не меняется: Cloudflare видит только зашифрованный
  поток MTProto, как и провайдер.
