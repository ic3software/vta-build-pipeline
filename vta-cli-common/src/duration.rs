//! Short duration parsing for CLI flags like `--admin-expires 7d`.
//!
//! Accepts `N[s|m|h|d|w]` — seconds, minutes, hours, days, weeks — or a
//! plain integer which is interpreted as seconds. Whitespace is trimmed.

use std::time::{SystemTime, UNIX_EPOCH};

/// Parse a duration string into seconds.
///
/// Recognised suffixes: `s` (seconds), `m` (minutes), `h` (hours),
/// `d` (days), `w` (weeks). An unsuffixed value is seconds.
///
/// Examples: `"30s" → 30`, `"5m" → 300`, `"24h" → 86400`, `"7d" → 604800`,
/// `"2w" → 1209600`, `"3600" → 3600`.
pub fn parse_duration_secs(s: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration value".into());
    }
    let (num_str, mult) = match s.as_bytes().last().copied() {
        Some(b's') => (&s[..s.len() - 1], 1u64),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b'h') => (&s[..s.len() - 1], 3600),
        Some(b'd') => (&s[..s.len() - 1], 86_400),
        Some(b'w') => (&s[..s.len() - 1], 604_800),
        Some(c) if c.is_ascii_digit() => (s, 1),
        _ => return Err(format!("invalid duration '{s}' (use N[s|m|h|d|w])").into()),
    };
    let n: u64 = num_str
        .parse()
        .map_err(|_| format!("invalid duration number in '{s}'"))?;
    if n == 0 {
        return Err("duration must be positive".into());
    }
    Ok(n.saturating_mul(mult))
}

/// Parse a duration and return the absolute unix-epoch expiry time
/// (`now + duration`).
pub fn duration_to_expires_at(s: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let secs = parse_duration_secs(s)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(now.saturating_add(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_unit() {
        assert_eq!(parse_duration_secs("30s").unwrap(), 30);
        assert_eq!(parse_duration_secs("5m").unwrap(), 300);
        assert_eq!(parse_duration_secs("2h").unwrap(), 7200);
        assert_eq!(parse_duration_secs("7d").unwrap(), 604_800);
        assert_eq!(parse_duration_secs("2w").unwrap(), 1_209_600);
        assert_eq!(parse_duration_secs("3600").unwrap(), 3600);
        assert_eq!(parse_duration_secs("  24h  ").unwrap(), 86_400);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_duration_secs("").is_err());
        assert!(parse_duration_secs("abc").is_err());
        assert!(parse_duration_secs("7x").is_err());
        assert!(parse_duration_secs("0h").is_err());
    }

    #[test]
    fn expiry_is_in_the_future() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expiry = duration_to_expires_at("60s").unwrap();
        assert!(expiry >= before + 60);
        assert!(expiry <= before + 65);
    }
}
