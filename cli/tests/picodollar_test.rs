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
    // 19 USD/Mtok would overflow u64 picodollar representation (~18.4 max)
    assert!(usd_per_mtok_to_pdollars("19").is_err());
}

#[test]
fn display_precision() {
    // 10_000_000_000 pUSD/Mtok = $0.01/Mtok
    let s = pdollars_to_usd_per_mtok(10_000_000_000);
    assert_eq!(s, "0.010000");
}
