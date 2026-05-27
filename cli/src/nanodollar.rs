//! USD/Mtok ↔ nano-dollar/Mtok conversion helpers.
//!
//! Human-facing prices are expressed as USD per million tokens (e.g., "3.00"
//! meaning $3.00/Mtok). Internally all prices are nano-dollars per million
//! tokens (nUSD/Mtok), stored as integer JSON Numbers per the
//! nano-dollar-denomination contract.
//!
//! Conversion: `price_ndollars_per_mtok = usd_per_mtok × 10⁹`
//!
//! Example: $3.00/Mtok → 3,000,000,000 nUSD/Mtok
//!
//! The maximum representable value in a u64 is ~18.4 billion USD/Mtok —
//! well above any current or foreseeable provider price.

use anyhow::{bail, Context, Result};

/// Number of fractional decimal digits in one US dollar measured in
/// nano-dollars: 1 USD = 10^9 nano-dollars.
const NANO_DECIMALS: usize = 9;

/// Nano-dollars in one US dollar: 10^[`NANO_DECIMALS`].
const NANO_PER_USD: u64 = 1_000_000_000;

/// Maximum USD/Mtok accepted by [`usd_per_mtok_to_ndollars`].
///
/// A cap well below `u64::MAX / NANO_PER_USD` (~1.8×10¹⁰ USD/Mtok). A
/// price above 1M USD/Mtok is far more likely a units mistake than a
/// real SKU, so it is rejected with a clear error.
const MAX_USD_PER_MTOK: u64 = 1_000_000;

/// Parse a human-supplied USD/Mtok string (e.g. "3.00", "0.25", "15")
/// and return nano-dollars per million tokens.
///
/// The conversion is done entirely on the decimal string — no floating
/// point — so every nano-dollar of a many-digit or sub-cent price is
/// preserved exactly. The integer and fractional parts are split on `.`,
/// the fractional part is right-padded (or truncated) to exactly 9
/// digits, and the concatenated digits are parsed as a `u64`.
///
/// # Errors
/// Returns an error if the input is empty, not a plain decimal number,
/// negative, carries more than one `.`, or exceeds [`MAX_USD_PER_MTOK`].
pub fn usd_per_mtok_to_ndollars(input: &str) -> Result<u64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("price must not be empty");
    }
    if trimmed.starts_with('-') {
        bail!("price must not be negative (got '{trimmed}')");
    }

    // Split the decimal into integer / fractional digit strings. A leading
    // `+` is accepted; anything else non-digit (after the single `.`) is
    // rejected so f64-style inputs like "3e5", "inf", "$3" are caught.
    let body = trimmed.strip_prefix('+').unwrap_or(trimmed);
    let mut parts = body.split('.');
    let int_part = parts.next().unwrap_or("");
    let frac_part = parts.next().unwrap_or("");
    if parts.next().is_some() {
        bail!("invalid price '{trimmed}' — expected a number like '3.00'");
    }
    if int_part.is_empty() && frac_part.is_empty() {
        bail!("invalid price '{trimmed}' — expected a number like '3.00'");
    }
    let all_digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if !all_digits(int_part) || !all_digits(frac_part) {
        bail!("invalid price '{trimmed}' — expected a number like '3.00'");
    }

    // Right-pad the fractional part to exactly NANO_DECIMALS digits;
    // truncate any digits finer than a nano-dollar.
    let mut frac = String::with_capacity(NANO_DECIMALS);
    frac.push_str(&frac_part[..frac_part.len().min(NANO_DECIMALS)]);
    while frac.len() < NANO_DECIMALS {
        frac.push('0');
    }

    // Reject prices above the cap before building the nano-dollar value.
    let int_digits = int_part.trim_start_matches('0');
    let over_cap = if int_digits.is_empty() {
        false
    } else {
        match int_digits.parse::<u64>() {
            Ok(int_value) => int_value > MAX_USD_PER_MTOK,
            Err(_) => true,
        }
    };
    if over_cap {
        bail!(
            "price {trimmed} USD/Mtok exceeds the maximum accepted value \
             ({MAX_USD_PER_MTOK} USD/Mtok)"
        );
    }

    let mut digits = String::with_capacity(int_digits.len() + NANO_DECIMALS);
    digits.push_str(int_digits);
    digits.push_str(&frac);
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Ok(0);
    }
    digits.parse::<u64>().with_context(|| {
        format!(
            "price '{trimmed}' exceeds the maximum representable value \
             in u64 nano-dollars"
        )
    })
}

/// Decimal places shown by the display helper. Six gives micro-dollar
/// granularity — enough for a human-readable price summary.
const DISPLAY_DECIMALS: usize = 6;

/// Divisor that drops the nano-dollar digits finer than the display
/// precision: 10^([`NANO_DECIMALS`] − [`DISPLAY_DECIMALS`]) = 10^3.
const DISPLAY_SCALE: u64 = 1_000;

/// Format nano-dollars/Mtok as a human-readable USD/Mtok string for display.
///
/// The integer USD part and the fractional part are formatted directly
/// from the `u64` with no floating point. The fraction is shown to six
/// decimal places (micro-dollar granularity); finer nano-dollar digits are
/// dropped from the display only — the stored `u64` is unaffected.
#[must_use]
pub fn ndollars_to_usd_per_mtok(ndollars: u64) -> String {
    let dollars = ndollars / NANO_PER_USD;
    // Nano-dollars within the current dollar, scaled down to the display
    // precision by dividing off the digits the six-place display omits.
    let frac = (ndollars % NANO_PER_USD) / DISPLAY_SCALE;
    format!("{dollars}.{frac:0>DISPLAY_DECIMALS$}")
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
            usd_per_mtok_to_ndollars("3.00").expect("valid input"),
            3_000_000_000
        );
    }

    #[test]
    fn converts_15_usd() {
        assert_eq!(
            usd_per_mtok_to_ndollars("15").expect("valid input"),
            15_000_000_000
        );
    }

    #[test]
    fn converts_fractional() {
        // $0.01 / Mtok (Gemini Flash-Lite cache read floor)
        assert_eq!(
            usd_per_mtok_to_ndollars("0.01").expect("valid input"),
            10_000_000
        );
    }

    #[test]
    fn rejects_negative() {
        assert!(usd_per_mtok_to_ndollars("-1").is_err());
    }

    #[test]
    fn rejects_non_numeric() {
        assert!(usd_per_mtok_to_ndollars("abc").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(usd_per_mtok_to_ndollars("").is_err());
    }

    #[test]
    fn roundtrip() {
        let ndollars = 3_750_000_u64;
        let usd_str = ndollars_to_usd_per_mtok(ndollars);
        // 3,750,000 nUSD/Mtok = $0.00375/Mtok
        assert!(usd_str.starts_with("0.003750"));
    }

    /// A price whose 9 fractional digits are all distinct must convert with
    /// no rounding — the value an f64 multiply silently corrupts.
    #[test]
    fn converts_full_nine_digit_fraction_exactly() {
        assert_eq!(
            usd_per_mtok_to_ndollars("0.123456789").expect("valid input"),
            123_456_789
        );
    }

    /// Digits finer than a nano-dollar are truncated, not rounded or rejected.
    #[test]
    fn truncates_beyond_nano_dollar_granularity() {
        assert_eq!(
            usd_per_mtok_to_ndollars("0.1234567899").expect("valid input"),
            123_456_789
        );
    }

    /// The cap boundary: exactly `MAX_USD_PER_MTOK` must convert; any
    /// integer dollar value above it must be rejected.
    #[test]
    fn boundary_max_usd_per_mtok() {
        let at_cap = format!("{MAX_USD_PER_MTOK}");
        assert_eq!(
            usd_per_mtok_to_ndollars(&at_cap).expect("cap value is accepted"),
            MAX_USD_PER_MTOK * NANO_PER_USD
        );
        let over_cap = format!("{}", MAX_USD_PER_MTOK + 1);
        assert!(
            usd_per_mtok_to_ndollars(&over_cap).is_err(),
            "a price above the cap must be rejected"
        );
    }
}
