//! Miner identity slug validation.
//!
//! `GM_MINER_ID` names the miner across the attestation server and the
//! RA-TLS provisioner. The rule mirrors the gm gateway's `gateway_id`
//! so the shared `AttestationInfo` shape and the RA-TLS certificate
//! subject carry a consistent identifier.

/// Maximum length of a miner identity slug.
const MAX_MINER_ID_LEN: usize = 64;

/// Validate the miner identity slug: lowercase alphanumeric + hyphens,
/// non-empty, `<= 64` chars.
///
/// # Errors
///
/// Returns a human-readable message naming the rule that was violated.
pub fn validate_miner_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("GM_MINER_ID must not be empty".to_owned());
    }
    if id.len() > MAX_MINER_ID_LEN {
        return Err(format!(
            "GM_MINER_ID must be <={MAX_MINER_ID_LEN} characters, got {}",
            id.len()
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!(
            "GM_MINER_ID must be lowercase alphanumeric or hyphens: {id:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_miner_id() {
        assert!(validate_miner_id("").is_err());
    }

    #[test]
    fn rejects_uppercase_miner_id() {
        assert!(validate_miner_id("GM-Miner-1").is_err());
    }

    #[test]
    fn rejects_overlong_miner_id() {
        assert!(validate_miner_id(&"a".repeat(65)).is_err());
    }

    #[test]
    fn accepts_canonical_miner_id() {
        assert!(validate_miner_id("gm-testnet-miner").is_ok());
    }
}
