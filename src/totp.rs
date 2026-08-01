use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn generate_seed() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    encode_base32(&bytes)
}

fn encode_base32(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u8);
    for &byte in data {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn decode_base32(text: &str) -> Option<Vec<u8>> {
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0u8);
    for c in text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
    {
        let c = c.to_ascii_uppercase();
        let value = B32.iter().position(|&x| x == c)? as u32;
        acc = (acc << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1u32 << bits).saturating_sub(1);
        }
    }
    Some(out)
}

pub fn valid_seed(seed: &str) -> bool {
    decode_base32(seed).is_some_and(|bytes| bytes.len() >= 16)
}

fn code_at(seed: &str, counter: u64) -> Option<String> {
    let key = decode_base32(seed)?;
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).ok()?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let value =
        (u32::from_be_bytes(digest[offset..offset + 4].try_into().ok()?) & 0x7fff_ffff) % 1_000_000;
    Some(format!("{value:06}"))
}

pub fn verify(seed: &str, provided: &str) -> bool {
    let provided = provided.trim();
    if provided.len() != 6 || !provided.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 30)
        .unwrap_or(0);
    [now.saturating_sub(1), now, now.saturating_add(1)]
        .into_iter()
        .filter_map(|counter| code_at(seed, counter))
        .any(|code| bool::from(code.as_bytes().ct_eq(provided.as_bytes())))
}

/// How many recently-accepted codes to remember. A code is only reusable
/// inside its own acceptance window, so three covers the ±1 step window with
/// room to spare.
const REPLAY_MEMORY: usize = 3;

/// Longest a remembered code can still be replayed: the ±1 step window is
/// 90 seconds wide, after which `verify` rejects it on its own and the entry
/// is only taking up space.
const REPLAY_WINDOW_SECS: u64 = 90;

/// Makes an accepted TOTP code single-use.
///
/// `verify` accepts the same code for as long as its time step is inside the
/// window, so a code observed in flight — or simply submitted twice — would
/// otherwise authenticate more than once. That is the whole property a
/// one-time password is supposed to have.
#[derive(Default)]
pub struct ReplayGuard {
    /// (code, unix seconds when accepted), newest last. Bounded by
    /// `REPLAY_MEMORY`, so this cannot grow.
    recent: std::sync::Mutex<std::collections::VecDeque<(String, u64)>>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a code that has just verified, returning `false` if it was
    /// already used. Call this only for codes that passed `verify`, so a
    /// wrong guess cannot evict the record of a real one.
    pub fn accept(&self, code: &str) -> bool {
        self.accept_at(code, now_secs())
    }

    fn accept_at(&self, code: &str, now: u64) -> bool {
        let code = code.trim();
        let mut recent = crate::util::lock(&self.recent);
        // Forget anything that `verify` would no longer accept anyway.
        recent.retain(|(_, at)| now.saturating_sub(*at) < REPLAY_WINDOW_SECS);
        if recent.iter().any(|(seen, _)| seen == code) {
            return false;
        }
        if recent.len() == REPLAY_MEMORY {
            recent.pop_front();
        }
        recent.push_back((code.to_string(), now));
        true
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn provisioning_uri(seed: &str, account: &str) -> String {
    let label: String = account
        .bytes()
        .flat_map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.') {
                vec![b as char]
            } else {
                format!("%{b:02X}").chars().collect()
            }
        })
        .collect();
    format!("otpauth://totp/webshell:{label}?secret={seed}&issuer=webshell&digits=6&period=30")
}

pub fn qr_svg(uri: &str) -> anyhow::Result<String> {
    let code = qrcode::QrCode::new(uri.as_bytes())?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(240, 240)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_round_trip() {
        let raw = b"12345678901234567890";
        assert_eq!(decode_base32(&encode_base32(raw)).unwrap(), raw);
    }

    #[test]
    fn hotp_rfc_vector() {
        let seed = encode_base32(b"12345678901234567890");
        assert_eq!(code_at(&seed, 1).as_deref(), Some("287082"));
    }

    #[test]
    fn an_accepted_code_cannot_be_used_again() {
        let g = ReplayGuard::new();
        assert!(g.accept_at("123456", 1000));
        assert!(!g.accept_at("123456", 1000), "same code, same instant");
        assert!(!g.accept_at(" 123456 ", 1030), "whitespace is not a new code");
        assert!(g.accept_at("654321", 1030), "a different code still works");
    }

    #[test]
    fn only_the_last_three_codes_are_remembered() {
        let g = ReplayGuard::new();
        for code in ["111111", "222222", "333333"] {
            assert!(g.accept_at(code, 1000));
        }
        assert!(!g.accept_at("111111", 1000));
        // A fourth pushes the oldest out — acceptable, because a code that old
        // is outside the verification window anyway.
        assert!(g.accept_at("444444", 1000));
        assert!(g.accept_at("111111", 1000), "111111 was evicted by 444444");
        // Remembering 111111 again evicted 222222 in turn; the newest three
        // are what is held.
        assert!(!g.accept_at("333333", 1000));
        assert!(!g.accept_at("444444", 1000));
    }

    #[test]
    fn entries_expire_with_the_verification_window() {
        let g = ReplayGuard::new();
        assert!(g.accept_at("123456", 1000));
        assert!(!g.accept_at("123456", 1000 + REPLAY_WINDOW_SECS - 1));
        // Past the window `verify` rejects the code on its own, so remembering
        // it would only make a legitimate future code collide.
        assert!(g.accept_at("123456", 1000 + REPLAY_WINDOW_SECS));
    }
}
