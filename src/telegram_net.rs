//! Какие адреса и имена принадлежат Telegram.
//!
//! От этого ответа зависит поведение LAN-режима: слушатель на сетевом адресе
//! пропускает только Telegram, всё остальное отклоняет. Значит ошибка в любую
//! сторону видна пользователю.
//!
//! Раньше проверка сравнивала два первых октета, то есть считала «телеграмом»
//! целиком `149.154.0.0/16`, `91.108.0.0/16`, `91.105.0.0/16` и `185.76.0.0/16`,
//! а IPv6 не знала вовсе. Отсюда два разных дефекта: чужие адреса внутри этих
//! сетей уходили в MTProto-туннель и умирали, а настоящие адреса Telegram по
//! IPv6 отклонялись как посторонние. Второе и выглядит как «на компьютере
//! работает, с телефона нет» (by-sonic/tglock#42): на loopback не-Telegram
//! адреса всё равно релеятся напрямую, поэтому там ошибка не проявляется.
//!
//! Список сетей — официальный, <https://core.telegram.org/resources/cidr.txt>,
//! сверен 19 августа 2026 года.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IPv4-сети Telegram: адрес сети и длина префикса.
const V4: &[(Ipv4Addr, u32)] = &[
    (Ipv4Addr::new(91, 105, 192, 0), 23),
    (Ipv4Addr::new(91, 108, 4, 0), 22),
    (Ipv4Addr::new(91, 108, 8, 0), 22),
    (Ipv4Addr::new(91, 108, 12, 0), 22),
    (Ipv4Addr::new(91, 108, 16, 0), 22),
    (Ipv4Addr::new(91, 108, 20, 0), 22),
    (Ipv4Addr::new(91, 108, 56, 0), 22),
    (Ipv4Addr::new(149, 154, 160, 0), 20),
    (Ipv4Addr::new(185, 76, 151, 0), 24),
];

/// IPv6-сети Telegram.
const V6: &[(Ipv6Addr, u32)] = &[
    (Ipv6Addr::new(0x2001, 0x67c, 0x4e8, 0, 0, 0, 0, 0), 48),
    (Ipv6Addr::new(0x2001, 0xb28, 0xf23c, 0, 0, 0, 0, 0), 48),
    (Ipv6Addr::new(0x2001, 0xb28, 0xf23d, 0, 0, 0, 0, 0), 48),
    (Ipv6Addr::new(0x2001, 0xb28, 0xf23f, 0, 0, 0, 0, 0), 48),
    (Ipv6Addr::new(0x2a0a, 0xf280, 0, 0, 0, 0, 0, 0), 32),
];

/// Домены Telegram, к которым SOCKS5-клиент может попроситься по имени.
///
/// Это веб-инфраструктура, а не дата-центры: обычный HTTPS, MTProto в нём нет.
/// Telegram ходит сюда за конфигурацией, превью ссылок и файлами CDN, и на
/// телефоне такие запросы идут через тот же прокси.
const HOSTS: &[&str] = &[
    "telegram.org",
    "t.me",
    "telegram.me",
    "telesco.pe",
    "cdn-telegram.org",
];

/// Принадлежит ли адрес Telegram.
pub fn is_telegram(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => in_v4(ip),
        // Клиент может прислать `::ffff:149.154.167.51` вместо IPv4-формы, и
        // это тот же самый адрес.
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => in_v4(ip),
            None => in_v6(ip),
        },
    }
}

/// Принадлежит ли имя Telegram.
///
/// Совпадение только по границе метки: `telegram.org.example.com` — чужой
/// домен, и разрешать его нельзя.
pub fn is_telegram_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    HOSTS.iter().any(|suffix| {
        host == *suffix
            || (host.len() > suffix.len()
                && host.ends_with(suffix)
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.')
    })
}

/// Номер дата-центра по адресу — запасной вариант, когда его не удалось
/// достать из init-пакета.
///
/// Это догадка, а не факт: одна и та же подсеть обслуживает несколько DC
/// (`149.154.175.x` — и DC1, и DC3). Настоящий номер приходит из init, и сюда
/// попадают только соединения, у которых init разобрать не вышло.
pub fn dc_from_ip(ip: IpAddr) -> Option<u16> {
    match ip {
        IpAddr::V4(ip) => dc_from_ipv4(ip),
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => dc_from_ipv4(ip),
            None => dc_from_ipv6(ip),
        },
    }
}

fn dc_from_ipv4(ip: Ipv4Addr) -> Option<u16> {
    if !in_v4(ip) {
        return None;
    }
    let octets = ip.octets();
    Some(match (octets[0], octets[1], octets[2]) {
        (149, 154, 160..=163) => 1,
        (149, 154, 164..=167) => 2,
        (149, 154, 168..=171) => 3,
        (149, 154, 172..=175) => 1,
        (91, 108, 56..=59) => 5,
        (91, 108, 8..=11) => 3,
        (91, 108, 12..=15) => 4,
        (91, 105, 192..=193) => 203,
        _ => 2,
    })
}

/// Адреса дата-центров имеют вид `2001:b28:f23d:f002::a`, где `f00N` —
/// номер DC. Для `2a0a:f280::/32` такого правила нет, и выдумывать его не
/// нужно: номер придёт из init.
fn dc_from_ipv6(ip: Ipv6Addr) -> Option<u16> {
    if !in_v6(ip) {
        return None;
    }
    let dc = ip.segments()[3].checked_sub(0xf000)?;
    matches!(dc, 1..=5).then_some(dc)
}

fn in_v4(ip: Ipv4Addr) -> bool {
    let value = u32::from(ip);
    V4.iter().any(|&(network, prefix)| {
        let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
        value & mask == u32::from(network) & mask
    })
}

fn in_v6(ip: Ipv6Addr) -> bool {
    let value = u128::from(ip);
    V6.iter().any(|&(network, prefix)| {
        let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
        value & mask == u128::from(network) & mask
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn known_data_centre_addresses_are_telegram() {
        for address in [
            "149.154.175.50", // DC1
            "149.154.167.51", // DC2
            "149.154.175.100",
            "149.154.167.91",
            "91.108.56.130", // DC5
            "91.105.192.100",
            "185.76.151.1",
        ] {
            assert!(is_telegram(ip(address)), "{address} принадлежит Telegram");
        }
    }

    /// Раньше сюда попадал весь `/16`, то есть десятки тысяч чужих адресов.
    #[test]
    fn neighbours_outside_the_published_blocks_are_not_telegram() {
        for address in [
            "149.154.159.255", // на один адрес ниже 149.154.160.0/20
            "149.154.176.0",   // на один выше
            "91.108.3.255",
            "91.108.24.0",
            "91.108.60.0",
            "91.105.194.0",
            "185.76.150.255",
            "185.76.152.0",
            "1.1.1.1",
        ] {
            assert!(!is_telegram(ip(address)), "{address} — не Telegram");
        }
    }

    #[test]
    fn block_edges_belong_to_the_block() {
        for address in [
            "149.154.160.0",
            "149.154.175.255",
            "91.108.4.0",
            "91.108.7.255",
            "185.76.151.0",
            "185.76.151.255",
        ] {
            assert!(is_telegram(ip(address)), "{address} — край блока Telegram");
        }
    }

    /// Из-за этого LAN-режим отклонял живой Telegram (by-sonic/tglock#42).
    #[test]
    fn ipv6_data_centres_are_telegram_too() {
        for address in [
            "2001:b28:f23d:f001::a",
            "2001:67c:4e8:f002::a",
            "2001:b28:f23d:f003::a",
            "2001:67c:4e8:f004::a",
            "2001:b28:f23f:f005::a",
            "2001:b28:f23c::1",
            "2a0a:f280:203:a::b",
        ] {
            assert!(is_telegram(ip(address)), "{address} принадлежит Telegram");
        }
        assert!(!is_telegram(ip("2606:4700:4700::1111")), "это Cloudflare");
        assert!(!is_telegram(ip("2001:b28:f23e::1")), "соседний префикс");
    }

    #[test]
    fn ipv4_mapped_form_is_the_same_address() {
        assert!(is_telegram(ip("::ffff:149.154.167.51")));
        assert!(!is_telegram(ip("::ffff:1.1.1.1")));
    }

    /// Поведение, на которое опирался предыдущий тест `dc_from_ip`.
    #[test]
    fn data_centre_guess_survives_the_stricter_membership_check() {
        assert_eq!(dc_from_ip(ip("149.154.160.1")), Some(1));
        assert_eq!(dc_from_ip(ip("149.154.167.255")), Some(2));
        assert_eq!(dc_from_ip(ip("91.108.58.1")), Some(5));
        assert_eq!(dc_from_ip(ip("1.1.1.1")), None);
    }

    #[test]
    fn data_centre_guess_reads_the_number_out_of_an_ipv6_address() {
        assert_eq!(dc_from_ip(ip("2001:67c:4e8:f002::a")), Some(2));
        assert_eq!(dc_from_ip(ip("2001:b28:f23f:f005::a")), Some(5));
        assert_eq!(
            dc_from_ip(ip("2a0a:f280:203:a::b")),
            None,
            "для этого префикса правила нет — лучше признаться, чем выдумать"
        );
    }

    #[test]
    fn telegram_hosts_are_matched_on_label_boundaries() {
        for host in [
            "telegram.org",
            "web.telegram.org",
            "core.telegram.org",
            "venus.web.telegram.org",
            "t.me",
            "TELEGRAM.ORG",
            "telegram.org.", // корневая точка в имени законна
            "cdn4.cdn-telegram.org",
        ] {
            assert!(is_telegram_host(host), "{host} — Telegram");
        }
    }

    #[test]
    fn lookalike_hosts_are_rejected() {
        for host in [
            "telegram.org.example.com",
            "nottelegram.org",
            "fakecdn-telegram.org",
            "t.me.evil.net",
            "example.com",
            "",
        ] {
            assert!(!is_telegram_host(host), "{host} — не Telegram");
        }
    }
}
