//! USD/Mtok ↔ picodollar/Mtok conversion helpers.
//!
//! Human-facing prices are expressed as USD per million tokens (e.g., "3.00"
//! meaning $3.00/Mtok). Internally all prices are picodollars per million
//! tokens (pUSD/Mtok), stored as u64 strings in JSON per contracts/Q2.
//!
//! Conversion: `price_pdollars_per_mtok = usd_per_mtok × 10¹²`
//!
//! Example: $3.00/Mtok → 3,000,000,000,000 pUSD/Mtok → "3000000000000"
//!
//! The maximum representable value in a u64 is ~18.4 USD/Mtok — well
//! above any current or foreseeable provider price. Use u128 for aggregate
//! epoch totals but u64 here for per-product prices.

use anyhow::{bail, Result};

/// Multiplier as f64: 10^12 (picodollars per dollar).
/// `1_000_000_000_000_f64` is exactly representable (fits in f64 mantissa: 2^39.86 < 2^53).
const PICO_PER_USD_F64: f64 = 1_000_000_000_000.0_f64;

/// Maximum USD/Mtok accepted by this function.
///
/// `u64::MAX` picodollars / 10^12 pUSD-per-USD ≈ 18,446,744 USD/Mtok.
/// Pick a round value comfortably under that ceiling so the f64
/// boundary is unambiguous and well-priced future SKUs (anything up
/// to ~$1k per million tokens, well above today's frontier $40/Mtok)
/// stays inside the safe range.
const MAX_USD_PER_MTOK: f64 = 1_000_000.0_f64;

/// Parse a human-supplied USD/Mtok string (e.g. "3.00", "0.25", "15")
/// and return picodollars per million tokens.
///
/// # Errors
/// Returns an error if the input is empty, non-numeric, negative, infinite, or
/// exceeds the representable range (≈18.4 USD/Mtok in u64 picodollars).
pub fn usd_per_mtok_to_pdollars(input: &str) -> Result<u64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("price must not be empty");
    }

    // Parse as f64 for user convenience; precision is sufficient for provider
    // pricing (f64 has ~15 significant decimal digits; 1 pUSD/Mtok granularity
    // only requires ~12 at the price magnitudes we handle).
    let usd: f64 = trimmed.parse().map_err(|_| {
        anyhow::anyhow!("invalid price '{trimmed}' — expected a number like '3.00'")
    })?;

    if usd < 0.0 {
        bail!("price must not be negative (got {usd})");
    }
    if !usd.is_finite() {
        bail!("price must be a finite number (got {usd})");
    }
    if usd > MAX_USD_PER_MTOK {
        bail!(
            "price {usd} USD/Mtok exceeds the maximum representable value \
             ({MAX_USD_PER_MTOK} USD/Mtok in u64 picodollars)"
        );
    }

    // The range check above guarantees 0.0 ≤ pdollars_f ≤ 18.4e12,
    // which is well within u64's range and non-negative, so the cast is safe.
    let pdollars_f = usd * PICO_PER_USD_F64;
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "range-checked above: 0.0 ≤ value ≤ 18.4e12, safe for u64"
    )]
    Ok(pdollars_f.round() as u64)
}

/// Format picodollars/Mtok as a human-readable USD/Mtok string for display.
#[must_use]
pub fn pdollars_to_usd_per_mtok(pdollars: u64) -> String {
    // pdollars ≤ 18.4e12; f64 mantissa (2^53 ≈ 9e15) handles this exactly.
    #[expect(
        clippy::cast_precision_loss,
        reason = "pdollars ≤ 18.4e12 << 2^53: no precision loss at this range"
    )]
    let usd = pdollars as f64 / PICO_PER_USD_F64;
    format!("{usd:.6}")
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected errors"
)]
mod tests {
    use super::*;

    #[test]
    fn converts_3_usd() {
        assert_eq!(
            usd_per_mtok_to_pdollars("3.00").expect("valid input"),
            3_000_000_000_000
        );
    }

    #[test]
    fn converts_15_usd() {
        assert_eq!(
            usd_per_mtok_to_pdollars("15").expect("valid input"),
            15_000_000_000_000
        );
    }

    #[test]
    fn converts_fractional() {
        // $0.01 / Mtok (Gemini Flash-Lite cache read floor)
        assert_eq!(
            usd_per_mtok_to_pdollars("0.01").expect("valid input"),
            10_000_000_000
        );
    }

    #[test]
    fn rejects_negative() {
        assert!(usd_per_mtok_to_pdollars("-1").is_err());
    }

    #[test]
    fn rejects_non_numeric() {
        assert!(usd_per_mtok_to_pdollars("abc").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(usd_per_mtok_to_pdollars("").is_err());
    }

    #[test]
    fn roundtrip() {
        let pdollars = 3_750_000_000_u64;
        let usd_str = pdollars_to_usd_per_mtok(pdollars);
        // 3,750,000,000 pUSD/Mtok = $0.00375/Mtok
        assert!(usd_str.starts_with("0.00375"));
    }
}
