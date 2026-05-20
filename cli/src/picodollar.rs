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

use anyhow::{bail, Context, Result};

/// Number of fractional decimal digits in one US dollar measured in
/// picodollars: 1 USD = 10^12 picodollars.
const PICO_DECIMALS: usize = 12;

/// Picodollars in one US dollar: 10^[`PICO_DECIMALS`].
const PICO_PER_USD: u64 = 1_000_000_000_000;

/// Maximum USD/Mtok accepted by [`usd_per_mtok_to_pdollars`].
///
/// `u64::MAX` picodollars is ≈18.4M USD/Mtok; this round cap sits well
/// under that and comfortably above any realistic frontier model price
/// (today's ceiling is ~$40/Mtok). A price above it is far more likely a
/// units mistake than a real SKU, so it is rejected with a clear error.
const MAX_USD_PER_MTOK: u64 = 1_000_000;

/// Parse a human-supplied USD/Mtok string (e.g. "3.00", "0.25", "15")
/// and return picodollars per million tokens.
///
/// The conversion is done entirely on the decimal string — no floating
/// point — so every picodollar of a many-digit or sub-cent price is
/// preserved exactly. The integer and fractional parts are split on `.`,
/// the fractional part is right-padded (or truncated) to exactly 12
/// digits, and the concatenated digits are parsed as a `u64`.
///
/// # Errors
/// Returns an error if the input is empty, not a plain decimal number,
/// negative, carries more than one `.`, or exceeds [`MAX_USD_PER_MTOK`].
pub fn usd_per_mtok_to_pdollars(input: &str) -> Result<u64> {
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

    // Right-pad the fractional part to exactly 12 digits (picodollar
    // granularity); truncate any digits finer than a picodollar.
    let mut frac = String::with_capacity(PICO_DECIMALS);
    frac.push_str(&frac_part[..frac_part.len().min(PICO_DECIMALS)]);
    while frac.len() < PICO_DECIMALS {
        frac.push('0');
    }

    // Reject prices above the cap before building the picodollar value.
    // `int_part` is all-digits; comparing it as a number catches an
    // out-of-range price even when the picodollar product would overflow.
    // An empty / all-zero integer part is zero; an int_part too large to
    // fit a u64 is, a fortiori, over the cap.
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

    // Concatenate the leading-zero-trimmed integer digits + 12 fractional
    // digits and parse as a u64. A fully-zero value trims to the empty
    // string and is handled by the fallback below.
    let mut digits = String::with_capacity(int_digits.len() + PICO_DECIMALS);
    digits.push_str(int_digits);
    digits.push_str(&frac);
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Ok(0);
    }
    digits.parse::<u64>().with_context(|| {
        format!(
            "price '{trimmed}' exceeds the maximum representable value \
             (~18.4 USD/Mtok in u64 picodollars)"
        )
    })
}

/// Decimal places shown by the display helper. Six gives micro-dollar
/// granularity — enough for a human-readable price summary.
const DISPLAY_DECIMALS: usize = 6;

/// Divisor that drops the picodollar digits finer than the display
/// precision: 10^([`PICO_DECIMALS`] − [`DISPLAY_DECIMALS`]) = 10^6.
const DISPLAY_SCALE: u64 = 1_000_000;

/// Format picodollars/Mtok as a human-readable USD/Mtok string for display.
///
/// The integer USD part and the fractional part are formatted directly
/// from the `u64` with no floating point. The fraction is shown to six
/// decimal places (micro-dollar granularity); finer picodollar digits are
/// dropped from the display only — the stored `u64` is unaffected.
#[must_use]
pub fn pdollars_to_usd_per_mtok(pdollars: u64) -> String {
    let dollars = pdollars / PICO_PER_USD;
    // Picodollars within the current dollar, scaled down to the display
    // precision by dividing off the digits the six-place display omits.
    let frac = (pdollars % PICO_PER_USD) / DISPLAY_SCALE;
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

    /// A price whose 12 fractional digits are all distinct must convert with
    /// no rounding — the value an f64 multiply silently corrupts.
    #[test]
    fn converts_full_twelve_digit_fraction_exactly() {
        assert_eq!(
            usd_per_mtok_to_pdollars("0.123456789012").expect("valid input"),
            123_456_789_012
        );
    }

    /// Digits finer than a picodollar are truncated, not rounded or rejected.
    #[test]
    fn truncates_beyond_picodollar_granularity() {
        assert_eq!(
            usd_per_mtok_to_pdollars("0.1234567890129").expect("valid input"),
            123_456_789_012
        );
    }

    /// The cap boundary: exactly `MAX_USD_PER_MTOK` must convert; any
    /// integer dollar value above it must be rejected.
    #[test]
    fn boundary_max_usd_per_mtok() {
        let at_cap = format!("{MAX_USD_PER_MTOK}");
        assert_eq!(
            usd_per_mtok_to_pdollars(&at_cap).expect("cap value is accepted"),
            MAX_USD_PER_MTOK * PICO_PER_USD
        );
        let over_cap = format!("{}", MAX_USD_PER_MTOK + 1);
        assert!(
            usd_per_mtok_to_pdollars(&over_cap).is_err(),
            "a price above the cap must be rejected"
        );
    }
}
