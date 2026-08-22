use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::path::Path;
#[cfg(not(test))]
use std::path::PathBuf;

type AesCtr = ctr::Ctr128BE<Aes256>;

const INIT_LEN: usize = 64;
const KEY_START: usize = 8;
const KEY_END: usize = 40;
const IV_END: usize = 56;
const TAG_START: usize = 56;
const DC_START: usize = 60;

const ABRIDGED: [u8; 4] = [0xef; 4];
const INTERMEDIATE: [u8; 4] = [0xee; 4];
const PADDED_INTERMEDIATE: [u8; 4] = [0xdd; 4];

pub struct ClientInit {
    pub dc: u16,
    pub media: bool,
    pub relay_init: [u8; INIT_LEN],
    pub crypto: CryptoContext,
}

pub struct CryptoContext {
    client_decrypt: AesCtr,
    client_encrypt: AesCtr,
    telegram_encrypt: AesCtr,
    telegram_decrypt: AesCtr,
}

impl CryptoContext {
    pub fn client_to_telegram(&mut self, data: &mut [u8]) {
        self.client_decrypt.apply_keystream(data);
        self.telegram_encrypt.apply_keystream(data);
    }

    pub fn telegram_to_client(&mut self, data: &mut [u8]) {
        self.telegram_decrypt.apply_keystream(data);
        self.client_encrypt.apply_keystream(data);
    }
}

pub fn generate_secret() -> [u8; 16] {
    let mut secret = [0; 16];
    OsRng.fill_bytes(&mut secret);
    secret
}

/// Секрет прокси и то, лежит ли он на диске.
pub struct StoredSecret {
    pub value: [u8; 16],
    /// Ошибка, из-за которой секрет не удалось сохранить.
    ///
    /// Если она есть, при следующем запуске секрет будет другим, ссылка
    /// `tg://proxy` перестанет совпадать с сохранённой в Telegram, и Telegram
    /// скажет «прокси настроен неверно и будет отключён». Раньше запись
    /// провалившись молчала, и понять причину было невозможно
    /// (by-sonic/tglock#37).
    pub write_error: Option<String>,
}

impl StoredSecret {
    /// Секрет действительно переживёт перезапуск.
    pub fn is_persistent(&self) -> bool {
        self.write_error.is_none()
    }
}

/// Взять секрет из файла, создав его, если файла нет или он испорчен.
///
/// Секрет — половина ссылки `tg://proxy`, поэтому сервис, придумывающий новый
/// при каждом старте, отключает всех уже настроенных клиентов.
pub fn load_or_create_secret_at(path: &Path) -> StoredSecret {
    if let Ok(value) = std::fs::read_to_string(path) {
        if let Some(value) = parse_secret_hex(value.trim()) {
            return StoredSecret {
                value,
                write_error: None,
            };
        }
    }

    let value = generate_secret();
    let write_error = store_secret(path, &secret_hex(&value))
        .err()
        .map(|error| format!("{}: {error}", path.display()));
    StoredSecret { value, write_error }
}

fn store_secret(path: &Path, value: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    write_secret_file(path, value)
}

#[cfg(not(test))]
pub fn load_or_create_secret() -> StoredSecret {
    match secret_path() {
        Some(path) => load_or_create_secret_at(&path),
        None => StoredSecret {
            value: generate_secret(),
            write_error: Some("не удалось определить папку для секрета в этой системе".to_owned()),
        },
    }
}

#[cfg(not(test))]
pub fn default_secret_path() -> Option<PathBuf> {
    secret_path()
}

#[cfg(not(test))]
fn secret_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|path| path.join("TGLock").join("secret"))
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|path| path.join("Library/Application Support/TGLock/secret"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
            return Some(PathBuf::from(path).join("tglock").join("secret"));
        }
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|path| path.join(".config/tglock/secret"))
    }
}

#[cfg(unix)]
fn write_secret_file(path: &Path, value: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(value.as_bytes())
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, value: &str) -> std::io::Result<()> {
    std::fs::write(path, value)
}

pub fn secret_hex(secret: &[u8; 16]) -> String {
    let mut output = String::with_capacity(32);
    for byte in secret {
        use std::fmt::Write;
        let _ = write!(output, "{:02x}", byte);
    }
    output
}

/// Разобрать секрет, записанный человеком.
///
/// Принимает и 32 hex-символа, и форму с префиксом `dd` — именно так секрет
/// выглядит в ссылке `tg://proxy`, откуда его и копируют.
pub fn parse_secret(value: &str) -> Option<[u8; 16]> {
    let trimmed = value.trim();
    let hex = trimmed
        .strip_prefix("dd")
        .filter(|rest| rest.len() == 32)
        .unwrap_or(trimmed);
    parse_secret_hex(hex)
}

fn parse_secret_hex(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }
    let mut secret = [0; 16];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(secret)
}

pub fn telegram_secret(secret: &[u8; 16]) -> String {
    format!("dd{}", secret_hex(secret))
}

pub fn parse_client_init(init: &[u8; INIT_LEN], secret: &[u8; 16]) -> Option<ClientInit> {
    let client_dec_key = secret_key(&init[KEY_START..KEY_END], secret);
    let client_dec_iv: [u8; 16] = init[KEY_END..IV_END].try_into().ok()?;
    let mut client_decrypt = AesCtr::new((&client_dec_key).into(), (&client_dec_iv).into());

    let mut decrypted = *init;
    client_decrypt.apply_keystream(&mut decrypted);
    let protocol_tag: [u8; 4] = decrypted[TAG_START..DC_START].try_into().ok()?;
    if !matches!(protocol_tag, ABRIDGED | INTERMEDIATE | PADDED_INTERMEDIATE) {
        return None;
    }

    let dc_index = i16::from_le_bytes([decrypted[DC_START], decrypted[DC_START + 1]]);
    let dc = dc_index.unsigned_abs();
    if !matches!(dc, 1..=5 | 203) {
        return None;
    }

    let relay_init = generate_relay_init(protocol_tag, dc_index);
    let crypto = build_crypto_context(init, secret, &relay_init)?;
    Some(ClientInit {
        dc,
        media: dc_index < 0,
        relay_init,
        crypto,
    })
}

fn secret_key(prekey: &[u8], secret: &[u8; 16]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(prekey);
    hash.update(secret);
    hash.finalize().into()
}

fn generate_relay_init(protocol_tag: [u8; 4], dc_index: i16) -> [u8; INIT_LEN] {
    loop {
        let mut init = [0; INIT_LEN];
        OsRng.fill_bytes(&mut init);
        if is_reserved_init(&init) {
            continue;
        }

        let key: [u8; 32] = init[KEY_START..KEY_END].try_into().unwrap();
        let iv: [u8; 16] = init[KEY_END..IV_END].try_into().unwrap();
        let mut cipher = AesCtr::new((&key).into(), (&iv).into());
        let mut encrypted = init;
        cipher.apply_keystream(&mut encrypted);

        let mut tail = [0; 8];
        tail[..4].copy_from_slice(&protocol_tag);
        tail[4..6].copy_from_slice(&dc_index.to_le_bytes());
        OsRng.fill_bytes(&mut tail[6..]);
        for index in 0..8 {
            init[TAG_START + index] ^= tail[index] ^ encrypted[TAG_START + index];
        }
        return init;
    }
}

fn is_reserved_init(init: &[u8; INIT_LEN]) -> bool {
    init[0] == 0xef
        || &init[..4] == b"HEAD"
        || &init[..4] == b"POST"
        || &init[..4] == b"GET "
        || init[..4] == [0xee; 4]
        || init[..4] == [0xdd; 4]
        || init[..4] == [0x16, 0x03, 0x01, 0x02]
        || init[4..8] == [0; 4]
}

fn build_crypto_context(
    client_init: &[u8; INIT_LEN],
    secret: &[u8; 16],
    relay_init: &[u8; INIT_LEN],
) -> Option<CryptoContext> {
    let client_dec_key = secret_key(&client_init[KEY_START..KEY_END], secret);
    let client_dec_iv: [u8; 16] = client_init[KEY_END..IV_END].try_into().ok()?;
    let mut client_decrypt = AesCtr::new((&client_dec_key).into(), (&client_dec_iv).into());
    client_decrypt.apply_keystream(&mut [0; INIT_LEN]);

    let reversed_client: Vec<_> = client_init[KEY_START..IV_END]
        .iter()
        .rev()
        .copied()
        .collect();
    let client_enc_key = secret_key(&reversed_client[..32], secret);
    let client_enc_iv: [u8; 16] = reversed_client[32..].try_into().ok()?;
    let client_encrypt = AesCtr::new((&client_enc_key).into(), (&client_enc_iv).into());

    let relay_enc_key: [u8; 32] = relay_init[KEY_START..KEY_END].try_into().ok()?;
    let relay_enc_iv: [u8; 16] = relay_init[KEY_END..IV_END].try_into().ok()?;
    let mut telegram_encrypt = AesCtr::new((&relay_enc_key).into(), (&relay_enc_iv).into());
    telegram_encrypt.apply_keystream(&mut [0; INIT_LEN]);

    let reversed_relay: Vec<_> = relay_init[KEY_START..IV_END]
        .iter()
        .rev()
        .copied()
        .collect();
    let relay_dec_key: [u8; 32] = reversed_relay[..32].try_into().ok()?;
    let relay_dec_iv: [u8; 16] = reversed_relay[32..].try_into().ok()?;
    let telegram_decrypt = AesCtr::new((&relay_dec_key).into(), (&relay_dec_iv).into());

    Some(CryptoContext {
        client_decrypt,
        client_encrypt,
        telegram_encrypt,
        telegram_decrypt,
    })
}

#[cfg(test)]
pub(crate) fn test_client_init(secret: &[u8; 16], dc_index: i16) -> [u8; INIT_LEN] {
    tests::generate_client_init(secret, PADDED_INTERMEDIATE, dc_index)
}

/// One end of an obfuscated2 stream, built the way the real peer builds it.
///
/// Lets tests assert on the bytes the peer actually observes rather than on the
/// proxy's own view of them, so a mistake that is symmetric inside
/// [`CryptoContext`] still fails the test.
#[cfg(test)]
pub(crate) struct TestPeer {
    encrypt: AesCtr,
    decrypt: AesCtr,
}

#[cfg(test)]
impl TestPeer {
    pub(crate) fn encrypt(&mut self, data: &mut [u8]) {
        self.encrypt.apply_keystream(data);
    }

    pub(crate) fn decrypt(&mut self, data: &mut [u8]) {
        self.decrypt.apply_keystream(data);
    }
}

/// The Telegram client: its keys come from the init it sent, salted with the
/// shared secret.
#[cfg(test)]
pub(crate) fn test_client_peer(init: &[u8; INIT_LEN], secret: &[u8; 16]) -> TestPeer {
    let key = secret_key(&init[KEY_START..KEY_END], secret);
    let iv: [u8; 16] = init[KEY_END..IV_END].try_into().unwrap();
    let mut encrypt = AesCtr::new((&key).into(), (&iv).into());
    encrypt.apply_keystream(&mut [0; INIT_LEN]);

    let reversed: Vec<u8> = init[KEY_START..IV_END].iter().rev().copied().collect();
    let decrypt_key = secret_key(&reversed[..32], secret);
    let decrypt_iv: [u8; 16] = reversed[32..].try_into().unwrap();
    let decrypt = AesCtr::new((&decrypt_key).into(), (&decrypt_iv).into());

    TestPeer { encrypt, decrypt }
}

/// The Telegram relay: no shared secret, keys come straight from the init the
/// proxy generated for it.
#[cfg(test)]
pub(crate) fn test_relay_peer(relay_init: &[u8; INIT_LEN]) -> TestPeer {
    let key: [u8; 32] = relay_init[KEY_START..KEY_END].try_into().unwrap();
    let iv: [u8; 16] = relay_init[KEY_END..IV_END].try_into().unwrap();
    let mut decrypt = AesCtr::new((&key).into(), (&iv).into());
    decrypt.apply_keystream(&mut [0; INIT_LEN]);

    let reversed: Vec<u8> = relay_init[KEY_START..IV_END]
        .iter()
        .rev()
        .copied()
        .collect();
    let encrypt_key: [u8; 32] = reversed[..32].try_into().unwrap();
    let encrypt_iv: [u8; 16] = reversed[32..].try_into().unwrap();
    let encrypt = AesCtr::new((&encrypt_key).into(), (&encrypt_iv).into());

    TestPeer { encrypt, decrypt }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn generate_client_init(
        secret: &[u8; 16],
        protocol_tag: [u8; 4],
        dc_index: i16,
    ) -> [u8; INIT_LEN] {
        let mut init = generate_relay_init(protocol_tag, dc_index);
        let key = secret_key(&init[KEY_START..KEY_END], secret);
        let iv: [u8; 16] = init[KEY_END..IV_END].try_into().unwrap();
        let mut cipher = AesCtr::new((&key).into(), (&iv).into());
        let mut encrypted = init;
        cipher.apply_keystream(&mut encrypted);

        let mut tail = [0; 8];
        tail[..4].copy_from_slice(&protocol_tag);
        tail[4..6].copy_from_slice(&dc_index.to_le_bytes());
        tail[6..].copy_from_slice(&[17, 23]);
        for index in 0..8 {
            init[TAG_START + index] ^= tail[index] ^ encrypted[TAG_START + index];
        }
        init
    }

    #[test]
    fn parses_secret_protected_media_init() {
        let secret = [42; 16];
        let init = generate_client_init(&secret, PADDED_INTERMEDIATE, -4);
        let parsed = parse_client_init(&init, &secret).unwrap();
        assert_eq!(parsed.dc, 4);
        assert!(parsed.media);
    }

    #[test]
    fn rejects_wrong_secret() {
        let init = generate_client_init(&[42; 16], INTERMEDIATE, 2);
        assert!(parse_client_init(&init, &[7; 16]).is_none());
    }

    #[test]
    fn telegram_link_secret_has_padded_intermediate_prefix() {
        assert_eq!(
            telegram_secret(&[0xab; 16]),
            "ddabababababababababababababababab"
        );
    }

    #[test]
    fn accepts_every_supported_protocol_tag() {
        let secret = [7; 16];
        for tag in [ABRIDGED, INTERMEDIATE, PADDED_INTERMEDIATE] {
            let init = generate_client_init(&secret, tag, 2);
            let parsed = parse_client_init(&init, &secret)
                .unwrap_or_else(|| panic!("tag {tag:02x?} must be accepted"));
            assert_eq!(parsed.dc, 2);
            assert!(!parsed.media);
        }
    }

    #[test]
    fn relay_init_carries_the_clients_protocol_tag_and_dc() {
        let secret = [3; 16];
        for (tag, dc_index) in [
            (ABRIDGED, 1_i16),
            (INTERMEDIATE, -5),
            (PADDED_INTERMEDIATE, 203),
        ] {
            let init = generate_client_init(&secret, tag, dc_index);
            let parsed = parse_client_init(&init, &secret).unwrap();

            // The relay init is freshly generated, never the client's bytes.
            assert_ne!(parsed.relay_init, init);

            // Decoding the relay init the way Telegram does must recover the
            // same protocol and data centre the client asked for.
            let key: [u8; 32] = parsed.relay_init[KEY_START..KEY_END].try_into().unwrap();
            let iv: [u8; 16] = parsed.relay_init[KEY_END..IV_END].try_into().unwrap();
            let mut cipher = AesCtr::new((&key).into(), (&iv).into());
            let mut decoded = parsed.relay_init;
            cipher.apply_keystream(&mut decoded);

            assert_eq!(decoded[TAG_START..DC_START], tag);
            assert_eq!(
                i16::from_le_bytes([decoded[DC_START], decoded[DC_START + 1]]),
                dc_index
            );
        }
    }

    #[test]
    fn rejects_data_centers_outside_the_known_range() {
        let secret = [11; 16];
        for dc_index in [0_i16, 6, -6, 204, -204, 1000] {
            let init = generate_client_init(&secret, INTERMEDIATE, dc_index);
            assert!(
                parse_client_init(&init, &secret).is_none(),
                "DC index {dc_index} must be rejected"
            );
        }
    }

    #[test]
    fn negative_index_marks_media_and_keeps_the_data_center() {
        let secret = [13; 16];
        for dc in [1_u16, 2, 3, 4, 5, 203] {
            let index = -(dc as i16);
            let parsed =
                parse_client_init(&generate_client_init(&secret, ABRIDGED, index), &secret)
                    .unwrap();
            assert_eq!(parsed.dc, dc);
            assert!(parsed.media);

            let parsed =
                parse_client_init(&generate_client_init(&secret, ABRIDGED, dc as i16), &secret)
                    .unwrap();
            assert_eq!(parsed.dc, dc);
            assert!(!parsed.media);
        }
    }

    #[test]
    fn plaintext_survives_the_trip_to_the_relay_and_back() {
        let secret = [42; 16];
        let init = generate_client_init(&secret, ABRIDGED, 2);
        let mut parsed = parse_client_init(&init, &secret).unwrap();
        let mut client = test_client_peer(&init, &secret);
        let mut relay = test_relay_peer(&parsed.relay_init);

        let request = b"exactly what Telegram must receive".to_vec();
        let mut wire = request.clone();
        client.encrypt(&mut wire);
        assert_ne!(wire, request, "the wire must not carry plaintext");
        parsed.crypto.client_to_telegram(&mut wire);
        assert_ne!(wire, request, "the upstream wire must not carry plaintext");
        relay.decrypt(&mut wire);
        assert_eq!(wire, request);

        let response = b"exactly what the client must receive".to_vec();
        let mut wire = response.clone();
        relay.encrypt(&mut wire);
        parsed.crypto.telegram_to_client(&mut wire);
        client.decrypt(&mut wire);
        assert_eq!(wire, response);
    }

    #[test]
    fn keystream_advances_across_chunks() {
        let secret = [5; 16];
        let init = generate_client_init(&secret, INTERMEDIATE, 3);
        let mut parsed = parse_client_init(&init, &secret).unwrap();
        let mut client = test_client_peer(&init, &secret);
        let mut relay = test_relay_peer(&parsed.relay_init);

        // A stream cipher is only correct if both ends stay in lockstep across
        // arbitrary chunk boundaries, which is how TCP actually delivers data.
        let chunks: [&[u8]; 4] = [b"one", b"", b"the third chunk is longer", b"4"];
        for chunk in chunks {
            let mut wire = chunk.to_vec();
            client.encrypt(&mut wire);
            parsed.crypto.client_to_telegram(&mut wire);
            relay.decrypt(&mut wire);
            assert_eq!(wire, chunk);
        }
    }

    #[test]
    fn reserved_prefixes_never_leave_the_generator() {
        // A relay init that starts with an HTTP verb or a protocol tag would be
        // misread by Telegram's frontend.
        for _ in 0..2_000 {
            assert!(!is_reserved_init(&generate_relay_init(ABRIDGED, 2)));
        }
    }

    #[test]
    fn a_failed_write_is_reported_instead_of_swallowed() {
        // Раньше ошибка записи выбрасывалась, секрет генерировался заново при
        // каждом запуске, и Telegram говорил «прокси настроен неверно» без
        // единой подсказки почему (by-sonic/tglock#37).
        let blocker = std::env::temp_dir().join(format!(
            "tglock-not-a-dir-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&blocker, "я файл, а не папка").unwrap();

        // Родитель пути — обычный файл, поэтому создать каталог невозможно.
        let stored = load_or_create_secret_at(&blocker.join("secret"));

        assert!(
            !stored.is_persistent(),
            "неудачная запись обязана быть видна"
        );
        let error = stored.write_error.expect("должно быть сообщение об ошибке");
        assert!(
            error.contains("secret"),
            "в сообщении должен быть путь, получено: {error}"
        );
        // Секрет всё равно выдан: прокси работает, просто до перезапуска.
        assert_ne!(stored.value, [0; 16]);

        let _ = std::fs::remove_file(&blocker);
    }

    #[test]
    fn a_successful_write_reports_no_error() {
        let path = std::env::temp_dir().join(format!(
            "tglock-secret-ok-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);

        let first = load_or_create_secret_at(&path);
        assert!(first.is_persistent(), "запись в temp должна удаваться");

        // Второй запуск читает готовый файл и тоже не жалуется.
        let second = load_or_create_secret_at(&path);
        assert!(second.is_persistent());
        assert_eq!(
            first.value, second.value,
            "секрет должен переживать перезапуск"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn accepts_a_secret_copied_from_a_tg_link() {
        let expected = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        // Обе формы: как в файле и как в ссылке tg://proxy.
        assert_eq!(
            parse_secret("00112233445566778899aabbccddeeff"),
            Some(expected)
        );
        assert_eq!(
            parse_secret("dd00112233445566778899aabbccddeeff"),
            Some(expected)
        );
        // Пробелы по краям — обычное дело при копировании.
        assert_eq!(
            parse_secret("  dd00112233445566778899aabbccddeeff\n"),
            Some(expected)
        );
        // Секрет, который сам начинается с dd и уже имеет полную длину, не
        // должен потерять первый байт: префикс снимается только если после него
        // остаётся ровно 32 символа.
        assert_eq!(
            parse_secret("dd112233445566778899aabbccddeeff"),
            Some([
                0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ])
        );
    }

    #[test]
    fn rejects_malformed_secrets() {
        for bad in [
            "",
            "dd",
            "слишком коротко",
            "00112233445566778899aabbccddee",     // 30 символов
            "00112233445566778899aabbccddeeffff", // 34 символа
            "zz112233445566778899aabbccddeeff",   // не hex
        ] {
            assert!(parse_secret(bad).is_none(), "{bad:?} должен быть отвергнут");
        }
    }

    #[test]
    fn parses_persisted_secret() {
        assert_eq!(
            parse_secret_hex("00112233445566778899aabbccddeeff"),
            Some([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ])
        );
        assert_eq!(parse_secret_hex("not-a-secret"), None);
    }
}
