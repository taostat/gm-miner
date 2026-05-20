//! Tests for USD/Mtok → picodollar conversion.
//! These test the hard contract that prices stay in pUSD/Mtok strings
//! (per contracts/Q2).

#![expect(
    clippy::unwrap_used,
    reason = "test assertions intentionally panic on unexpected errors"
)]

use gm_miner_cli::picodollar::{pdollars_to_usd_per_mtok, usd_per_mtok_to_pdollars};

#[test]
fn anthropic_input_3_usd() {
    // $3.00/Mtok → 3,000,000,000,000 pUSD/Mtok
    assert_eq!(usd_per_mtok_to_pdollars("3.00").unwrap(), 3_000_000_000_000);
}

#[test]
fn anthropic_output_15_usd() {
    // $15/Mtok → 15,000,000,000,000 pUSD/Mtok
    assert_eq!(usd_per_mtok_to_pdollars("15").unwrap(), 15_000_000_000_000);
}

#[test]
fn gemini_flash_lite_cache_read_floor() {
    // $0.01/Mtok = 10,000,000,000 pUSD/Mtok (≥1000× headroom, per spec §16)
    assert_eq!(usd_per_mtok_to_pdollars("0.01").unwrap(), 10_000_000_000);
}

#[test]
fn anthropic_cache_write_5m() {
    // $3.75/Mtok → 3,750,000,000,000 pUSD/Mtok
    assert_eq!(usd_per_mtok_to_pdollars("3.75").unwrap(), 3_750_000_000_000);
}

#[test]
fn openai_gpt5_input_fractional() {
    // $2.50/Mtok → 2,500,000,000,000 pUSD/Mtok
    assert_eq!(usd_per_mtok_to_pdollars("2.50").unwrap(), 2_500_000_000_000);
}

#[test]
fn zero_is_valid() {
    // A price of $0 (free) is represented as 0 pUSD.
    assert_eq!(usd_per_mtok_to_pdollars("0").unwrap(), 0);
    assert_eq!(usd_per_mtok_to_pdollars("0.00").unwrap(), 0);
}

#[test]
fn negative_rejected() {
    assert!(usd_per_mtok_to_pdollars("-1").is_err());
    assert!(usd_per_mtok_to_pdollars("-0.01").is_err());
}

#[test]
fn non_numeric_rejected() {
    assert!(usd_per_mtok_to_pdollars("abc").is_err());
    assert!(usd_per_mtok_to_pdollars("$3").is_err());
    assert!(usd_per_mtok_to_pdollars("3.00/Mtok").is_err());
}

#[test]
fn empty_rejected() {
    assert!(usd_per_mtok_to_pdollars("").is_err());
    assert!(usd_per_mtok_to_pdollars("   ").is_err());
}

#[test]
fn roundtrip_3_usd() {
    let pdollars = usd_per_mtok_to_pdollars("3.00").unwrap();
    let back = pdollars_to_usd_per_mtok(pdollars);
    // Should produce "3.000000" (formatted to 6dp)
    assert!(back.starts_with("3."), "got {back}");
}

#[test]
fn overflow_rejected() {
    // 2_000_000 USD/Mtok exceeds the CLI's MAX_USD_PER_MTOK cap of
    // 1_000_000, which is well below u64::MAX/10^12 (~18.4M) but
    // comfortably above any realistic frontier model price.
    assert!(usd_per_mtok_to_pdollars("2000000").is_err());
}

#[test]
fn display_precision() {
    // 10_000_000_000 pUSD/Mtok = $0.01/Mtok
    let s = pdollars_to_usd_per_mtok(10_000_000_000);
    assert_eq!(s, "0.010000");
}

// ── Exact decimal-string conversion (no f64 precision loss) ──────────────────

/// A price with all twelve fractional digits distinct exercises the full
/// picodollar resolution. An f64 multiply silently corrupts the low digits;
/// the exact string conversion must reproduce every one.
#[test]
fn full_twelve_digit_fraction_is_exact() {
    assert_eq!(
        usd_per_mtok_to_pdollars("0.123456789012").unwrap(),
        123_456_789_012
    );
}

/// A sub-cent price with a long fraction must keep every picodollar.
/// `0.000000000007` = 7 picodollars — below f64's reliable resolution at
/// the magnitudes here once multiplied.
#[test]
fn single_picodollar_sub_cent_price_is_exact() {
    assert_eq!(usd_per_mtok_to_pdollars("0.000000000007").unwrap(), 7);
}

/// A price with more than twelve fractional digits truncates the excess
/// (finer than a picodollar) rather than rounding or erroring.
#[test]
fn fraction_finer_than_picodollar_is_truncated() {
    assert_eq!(
        usd_per_mtok_to_pdollars("0.1234567890129").unwrap(),
        123_456_789_012
    );
}

/// A many-digit integer-and-fraction price must convert with no rounding.
#[test]
fn many_digit_price_is_exact() {
    // $123.456789012345/Mtok → 123_456_789_012_345 pUSD (fraction truncated
    // to 12 digits: "456789012345").
    assert_eq!(
        usd_per_mtok_to_pdollars("123.456789012345").unwrap(),
        123_456_789_012_345
    );
}

/// The cap boundary: exactly the maximum accepted dollar value converts,
/// one whole dollar above it is rejected.
#[test]
fn cap_boundary_is_exact() {
    // 1_000_000 USD/Mtok is the cap → 1e18 pUSD.
    assert_eq!(
        usd_per_mtok_to_pdollars("1000000").unwrap(),
        1_000_000_000_000_000_000
    );
    assert!(usd_per_mtok_to_pdollars("1000001").is_err());
}

/// Scientific notation and other f64-isms must be rejected — only plain
/// decimal strings are accepted now that there is no f64 parse.
#[test]
fn scientific_notation_rejected() {
    assert!(usd_per_mtok_to_pdollars("3e5").is_err());
    assert!(usd_per_mtok_to_pdollars("inf").is_err());
    assert!(usd_per_mtok_to_pdollars("NaN").is_err());
    assert!(usd_per_mtok_to_pdollars("3.0.0").is_err());
}

/// A plain "." with no digits on either side is not a number.
#[test]
fn bare_dot_rejected() {
    assert!(usd_per_mtok_to_pdollars(".").is_err());
}
