//! Файл конфигурации для `tglock-cli`.
//!
//! Запрошен в by-sonic/tglock#32: держать все параметры и секрет в одном месте,
//! чтобы не собирать батник с ключами при каждом запуске.
//!
//! Порядок приоритетов: значения по умолчанию → файл → флаги командной строки.
//! Флаги-переключатели (`--lan`, `--allow-direct`, `--quiet`) могут только
//! включать: их отсутствие означает «взять из файла», а не «выключить».

use serde::Deserialize;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use tglock::config::ListenConfig;
use tglock::{mtproto, proxy};

/// Имя файла, который ищется рядом с бинарём, если `--config` не задан.
pub const DEFAULT_FILE_NAME: &str = "tglock.toml";

/// Содержимое файла конфигурации.
///
/// `deny_unknown_fields` намеренно: опечатка вроде `porrt = 1080` должна быть
/// ошибкой при старте, а не молча проигнорированной строкой, из-за которой
/// сервис слушает не тот порт.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub bind: Option<IpAddr>,
    pub port: Option<u16>,
    pub lan: Option<bool>,
    pub allow_direct: Option<bool>,
    pub worker: Option<Vec<String>>,
    pub secret: Option<String>,
    pub secret_file: Option<PathBuf>,
    pub quiet: Option<bool>,
}

impl FileConfig {
    pub fn parse(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|error| format!("конфиг разобрать не удалось: {error}"))
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("не удалось прочитать {}: {error}", path.display()))?;
        Self::parse(&text)
    }
}

/// Значения, пришедшие из командной строки.
#[derive(Debug, Default)]
pub struct Overrides {
    pub bind: Option<IpAddr>,
    pub port: Option<u16>,
    pub lan: bool,
    pub allow_direct: bool,
    pub worker: Vec<String>,
    pub secret_file: Option<PathBuf>,
    pub quiet: bool,
}

/// Откуда взять секрет прокси.
#[derive(Debug, PartialEq)]
pub enum SecretSource {
    /// Записан прямо в конфиге.
    Inline([u8; 16]),
    /// Лежит в отдельном файле, создаётся при первом запуске.
    File(PathBuf),
    /// Ни того, ни другого: секрет будет новым при каждом старте.
    Ephemeral,
}

/// Итоговые настройки запуска.
#[derive(Debug, PartialEq)]
pub struct Resolved {
    pub listen: ListenConfig,
    /// Домены Worker'ов в том виде, в каком их ждёт `Stats::set_worker_domain`.
    pub workers: String,
    pub secret: SecretSource,
    pub quiet: bool,
}

impl Resolved {
    pub fn stats(&self) -> std::sync::Arc<proxy::Stats> {
        let stats = match &self.secret {
            SecretSource::Inline(secret) => proxy::Stats::with_secret(*secret),
            SecretSource::File(path) => {
                proxy::Stats::with_secret(mtproto::load_or_create_secret_at(path))
            }
            SecretSource::Ephemeral => proxy::Stats::new(),
        };
        stats.set_worker_domain(&self.workers);
        stats
    }
}

/// Свести файл и флаги в одни настройки.
pub fn resolve(file: FileConfig, cli: Overrides) -> Result<Resolved, String> {
    let port = cli.port.or(file.port).unwrap_or(proxy::DEFAULT_PORT);
    if port == 0 {
        return Err("порт должен быть от 1 до 65535".to_owned());
    }

    let lan = cli.lan || file.lan.unwrap_or(false);
    let bind = cli.bind.or(file.bind);
    if lan && bind.is_some() {
        return Err("нельзя задать одновременно lan и bind: выберите одно".to_owned());
    }

    let listen = match (lan, bind) {
        (true, _) => ListenConfig::lan(port),
        (false, Some(ip)) => ListenConfig::new(ip, port),
        (false, None) => ListenConfig::loopback(port),
    };
    let allow_direct = cli.allow_direct || file.allow_direct.unwrap_or(false);
    let listen = if allow_direct {
        listen.with_allow_direct(true)
    } else {
        listen
    };

    let workers = if cli.worker.is_empty() {
        file.worker.unwrap_or_default()
    } else {
        cli.worker
    };

    // Секрет из файла конфигурации важнее отдельного файла: если человек вписал
    // его сюда, значит хотел держать всё в одном месте.
    let secret = match (&file.secret, cli.secret_file.or(file.secret_file)) {
        (Some(value), _) => SecretSource::Inline(
            mtproto::parse_secret(value)
                .ok_or("секрет в конфиге неверный: нужны 32 hex-символа, можно с префиксом dd")?,
        ),
        (None, Some(path)) => SecretSource::File(path),
        (None, None) => SecretSource::Ephemeral,
    };

    Ok(Resolved {
        listen,
        workers: workers.join(","),
        secret,
        quiet: cli.quiet || file.quiet.unwrap_or(false),
    })
}

/// Путь к конфигу рядом с исполняемым файлом.
///
/// Именно этого просили в #32: «размещение рядом с бинарником частично решает
/// вопрос». Текущий каталог не используется, чтобы сервис не зависел от того,
/// откуда его запустили.
pub fn path_next_to_executable() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    Some(executable.parent()?.join(DEFAULT_FILE_NAME))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "00112233445566778899aabbccddeeff";

    fn cli() -> Overrides {
        Overrides::default()
    }

    #[test]
    fn empty_config_and_no_flags_give_the_documented_defaults() {
        let resolved = resolve(FileConfig::default(), cli()).unwrap();
        assert_eq!(resolved.listen.addr.to_string(), "127.0.0.1:1080");
        assert!(resolved.listen.allow_direct);
        assert_eq!(resolved.workers, "");
        assert_eq!(resolved.secret, SecretSource::Ephemeral);
        assert!(!resolved.quiet);
    }

    #[test]
    fn file_values_are_used_when_no_flags_are_given() {
        let file = FileConfig::parse(
            r#"
            bind = "10.0.0.5"
            port = 1443
            allow_direct = true
            worker = ["a.workers.dev", "b.workers.dev"]
            quiet = true
        "#,
        )
        .unwrap();
        let resolved = resolve(file, cli()).unwrap();
        assert_eq!(resolved.listen.addr.to_string(), "10.0.0.5:1443");
        assert!(resolved.listen.allow_direct);
        assert_eq!(resolved.workers, "a.workers.dev,b.workers.dev");
        assert!(resolved.quiet);
    }

    #[test]
    fn flags_win_over_the_file() {
        let file = FileConfig::parse(
            r#"
            bind = "10.0.0.5"
            port = 1443
            worker = ["from-file.workers.dev"]
        "#,
        )
        .unwrap();
        let resolved = resolve(
            file,
            Overrides {
                bind: Some("192.168.1.7".parse().unwrap()),
                port: Some(2080),
                worker: vec!["from-flag.workers.dev".to_owned()],
                ..Overrides::default()
            },
        )
        .unwrap();
        assert_eq!(resolved.listen.addr.to_string(), "192.168.1.7:2080");
        assert_eq!(resolved.workers, "from-flag.workers.dev");
    }

    #[test]
    fn a_switch_flag_can_only_turn_things_on() {
        // Отсутствие --quiet не должно отменять quiet = true из файла: иначе
        // файл нельзя было бы использовать для включения ничего.
        let file = FileConfig::parse("quiet = true\nallow_direct = true").unwrap();
        let resolved = resolve(file, cli()).unwrap();
        assert!(resolved.quiet);
        assert!(resolved.listen.allow_direct);
    }

    #[test]
    fn lan_from_the_file_restricts_to_telegram() {
        let resolved = resolve(FileConfig::parse("lan = true").unwrap(), cli()).unwrap();
        assert_eq!(resolved.listen.addr.to_string(), "0.0.0.0:1080");
        assert!(
            !resolved.listen.allow_direct,
            "сетевой слушатель не должен релеить произвольные адреса без явного разрешения"
        );
    }

    #[test]
    fn lan_and_bind_together_are_rejected_wherever_they_come_from() {
        let both_in_file = FileConfig::parse("lan = true\nbind = \"10.0.0.5\"").unwrap();
        assert!(resolve(both_in_file, cli()).is_err());

        let file = FileConfig::parse("bind = \"10.0.0.5\"").unwrap();
        let flag_lan = Overrides {
            lan: true,
            ..Overrides::default()
        };
        assert!(
            resolve(file, flag_lan).is_err(),
            "конфликт должен ловиться и когда стороны пришли из разных мест"
        );
    }

    #[test]
    fn inline_secret_is_accepted_in_both_written_forms() {
        for value in [SECRET.to_owned(), format!("dd{SECRET}")] {
            let file = FileConfig::parse(&format!("secret = \"{value}\"")).unwrap();
            let resolved = resolve(file, cli()).unwrap();
            assert_eq!(
                resolved.secret,
                SecretSource::Inline([
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ]),
                "форма {value} должна приниматься"
            );
        }
    }

    #[test]
    fn a_broken_inline_secret_stops_the_start() {
        let file = FileConfig::parse("secret = \"явно не секрет\"").unwrap();
        let error = resolve(file, cli()).unwrap_err();
        assert!(
            error.contains("32"),
            "ошибка должна объяснять формат, получено: {error}"
        );
    }

    #[test]
    fn inline_secret_wins_over_a_secret_file() {
        let file =
            FileConfig::parse(&format!("secret = \"{SECRET}\"\nsecret_file = \"s.bin\"")).unwrap();
        let resolved = resolve(file, cli()).unwrap();
        assert!(matches!(resolved.secret, SecretSource::Inline(_)));
    }

    #[test]
    fn secret_file_from_the_flag_wins_over_the_file() {
        let file = FileConfig::parse("secret_file = \"from-file.bin\"").unwrap();
        let resolved = resolve(
            file,
            Overrides {
                secret_file: Some(PathBuf::from("from-flag.bin")),
                ..Overrides::default()
            },
        )
        .unwrap();
        assert_eq!(
            resolved.secret,
            SecretSource::File(PathBuf::from("from-flag.bin"))
        );
    }

    #[test]
    fn a_typo_in_the_config_is_an_error_not_a_silent_default() {
        // Самая опасная поломка конфига — та, которую не видно. Сервис не должен
        // слушать 1080, если человек написал porrt = 1443.
        let error = FileConfig::parse("porrt = 1443").unwrap_err();
        assert!(
            error.contains("porrt"),
            "ошибка должна называть неизвестное поле, получено: {error}"
        );
    }

    #[test]
    fn malformed_values_are_rejected() {
        for text in [
            "bind = \"не адрес\"",
            "port = \"1080\"",
            "port = 70000",
            "worker = \"строка вместо списка\"",
            "lan = \"да\"",
        ] {
            assert!(
                FileConfig::parse(text).is_err(),
                "{text:?} должен быть отвергнут"
            );
        }
    }

    #[test]
    fn zero_port_is_rejected() {
        assert!(resolve(FileConfig::parse("port = 0").unwrap(), cli()).is_err());
    }

    #[test]
    fn comments_and_blank_lines_are_fine() {
        let file = FileConfig::parse(
            r#"
            # порт для второго экземпляра
            port = 1081

            # свой воркер как резерв
            worker = ["backup.workers.dev"]
        "#,
        )
        .unwrap();
        assert_eq!(file.port, Some(1081));
        assert_eq!(
            file.worker.as_deref(),
            Some(&["backup.workers.dev".to_owned()][..])
        );
    }
}
