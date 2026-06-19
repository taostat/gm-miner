//! Discount/price conversion: decimal-percent ⇄ integer basis-points and
//! per-Mtok nano-dollar rendering. All arithmetic is integer-only — money
//! is nano-dollars (1 nUSD = 10⁻⁹ USD per Mtok), never a float.

use anyhow::Result;

use crate::types::RetailDimensions;

/// Inclusive upper bound on `discount_bp`. The registry's pydantic schema
/// pins the same value (`registry/.../schemas.py::ProductDeclarationRequest`);
/// kept in sync by the API-shape pin in the PR plan §3.1.
pub const MAX_DISCOUNT_BP: u32 = 9_990;

/// clap `value_parser` for `--discount-pct`.
///
/// Parses a percent string with up to two decimal places into the registry's
/// integer basis-point wire value without floating-point arithmetic.
///
/// # Errors
///
/// Returns a message when the string is not a percent in `[0, 99.90]` with at
/// most two decimal places.
pub fn parse_discount_pct(s: &str) -> Result<u32, String> {
    let mut parts = s.split('.');
    let whole_s = parts.next().unwrap_or_default();
    let cents_s = parts.next();
    if parts.next().is_some() {
        return Err(format!(
            "invalid --discount-pct {s:?}: use a percent in [0, 99.90] with at most one decimal point"
        ));
    }
    if whole_s.is_empty() || !whole_s.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!(
            "invalid --discount-pct {s:?}: whole percent must be non-negative digits"
        ));
    }

    let whole = whole_s
        .parse::<u32>()
        .map_err(|_| format!("invalid --discount-pct {s:?}: whole percent is too large"))?;
    let cents = match cents_s {
        None | Some("") => 0,
        Some(cents_s) if cents_s.len() > 2 => {
            return Err(format!(
                "invalid --discount-pct {s:?}: use at most 2 decimal places"
            ));
        }
        Some(cents_s) if cents_s.chars().all(|c| c.is_ascii_digit()) => {
            let cents = cents_s.parse::<u32>().map_err(|_| {
                format!("invalid --discount-pct {s:?}: decimal percent is not parseable")
            })?;
            if cents_s.len() == 1 {
                cents * 10
            } else {
                cents
            }
        }
        _ => {
            return Err(format!(
                "invalid --discount-pct {s:?}: decimal percent must contain digits only"
            ));
        }
    };

    let parsed = whole
        .checked_mul(100)
        .and_then(|v| v.checked_add(cents))
        .ok_or_else(|| format!("invalid --discount-pct {s:?}: percent is too large"))?;
    if parsed > MAX_DISCOUNT_BP {
        return Err(format!(
            "--discount-pct {s:?} is above the cap of 99.90%; \
             the registry rejects anything above {MAX_DISCOUNT_BP} bp"
        ));
    }
    Ok(parsed)
}

#[must_use]
pub fn format_discount_pct(discount_bp: u32) -> String {
    let whole = discount_bp / 100;
    let cents = discount_bp % 100;
    if cents == 0 {
        return whole.to_string();
    }
    format!("{whole}.{cents:02}")
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_owned()
}

/// Effective per-Mtok ndollars the miner receives for one dimension:
/// `floor(retail × (10_000 − discount_bp) / 10_000)`. Matches the
/// gateway's per-dimension floor in `gateway/src/money/settle.rs::
/// effective_per_mtok_prices`, so what we display here is byte-for-byte
/// the number the miner is paid.
#[must_use]
pub fn effective_per_mtok_ndollars(retail_ndollars: u64, discount_bp: u32) -> u64 {
    let bp = u128::from(discount_bp.min(MAX_DISCOUNT_BP));
    let total = u128::from(retail_ndollars);
    let effective = (total * (10_000 - bp)) / 10_000;
    u64::try_from(effective).unwrap_or(retail_ndollars)
}

/// Render a per-Mtok ndollar value as a dollar amount with 3 decimal
/// places (e.g. `3_000_000_000 → "$3.000"`, `2_685_000_000 → "$2.685"`).
/// One nano-dollar is `10^-9` USD; 3 decimals is one-tenth of a cent
/// per Mtok, which is the resolution the operator actually cares about.
#[must_use]
pub fn format_per_mtok_usd(ndollars: u64) -> String {
    let dollars = ndollars / 1_000_000_000;
    let millis = (ndollars % 1_000_000_000) / 1_000_000;
    format!("${dollars}.{millis:03}")
}

/// One-line summary of the per-Mtok rate the miner will receive on a
/// product, given retail dimensions and a discount. Shared between
/// the single-product declaration output and the fan-out summary so
/// every site renders the same shape.
#[must_use]
pub fn effective_rate_summary(retail: &RetailDimensions, discount_bp: u32) -> String {
    let eff_in = effective_per_mtok_ndollars(retail.input_per_mtok_ndollars, discount_bp);
    let eff_out = effective_per_mtok_ndollars(retail.output_per_mtok_ndollars, discount_bp);
    format!(
        "{} in / {} out per Mtok",
        format_per_mtok_usd(eff_in),
        format_per_mtok_usd(eff_out)
    )
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests intentionally panic on unexpected values"
)]
mod tests {
    use super::{
        effective_per_mtok_ndollars, effective_rate_summary, format_discount_pct,
        format_per_mtok_usd, parse_discount_pct, MAX_DISCOUNT_BP,
    };
    use crate::types::RetailDimensions;

    #[test]
    fn discount_pct_accepts_examples() {
        assert_eq!(parse_discount_pct("0").unwrap(), 0);
        assert_eq!(parse_discount_pct("5").unwrap(), 500);
        assert_eq!(parse_discount_pct("10.5").unwrap(), 1050);
        assert_eq!(parse_discount_pct("10.55").unwrap(), 1055);
        assert_eq!(parse_discount_pct("99.90").unwrap(), MAX_DISCOUNT_BP);
    }

    #[test]
    fn discount_pct_rejects_negative() {
        let err = parse_discount_pct("-0.1").unwrap_err();
        assert!(err.contains("non-negative"), "got: {err}");
    }

    #[test]
    fn discount_pct_rejects_above_cap() {
        let err = parse_discount_pct("99.91").unwrap_err();
        assert!(err.contains("above the cap"), "got: {err}");
    }

    #[test]
    fn discount_pct_rejects_more_than_two_decimals() {
        let err = parse_discount_pct("10.555").unwrap_err();
        assert!(err.contains("at most 2 decimal"), "got: {err}");
    }

    #[test]
    fn discount_pct_rejects_unparseable() {
        let err = parse_discount_pct("abc").unwrap_err();
        assert!(err.contains("digits"), "got: {err}");
    }

    #[test]
    fn discount_pct_rejects_malformed() {
        let err = parse_discount_pct("10.5.5").unwrap_err();
        assert!(err.contains("at most one decimal point"), "got: {err}");
    }

    #[test]
    fn format_discount_pct_trims_trailing_zeroes() {
        assert_eq!(format_discount_pct(1050), "10.5");
        assert_eq!(format_discount_pct(1055), "10.55");
        assert_eq!(format_discount_pct(500), "5");
        assert_eq!(format_discount_pct(9990), "99.9");
        assert_eq!(format_discount_pct(0), "0");
        // 10_000 bp is what we keep when discount = 0, used by the
        // "you keep X% of retail" line in declare-product output.
        assert_eq!(format_discount_pct(10_000), "100");
        assert_eq!(format_discount_pct(10), "0.1");
    }

    #[test]
    fn effective_per_mtok_matches_gateway_floor() {
        // 6% discount on $3/Mtok retail → $2.82/Mtok per gateway settle.rs.
        assert_eq!(
            effective_per_mtok_ndollars(3_000_000_000, 600),
            2_820_000_000
        );
        // 10.5% discount on $3/Mtok input → $2.685/Mtok.
        assert_eq!(
            effective_per_mtok_ndollars(3_000_000_000, 1050),
            2_685_000_000
        );
        // Discount = 0 returns retail verbatim.
        assert_eq!(
            effective_per_mtok_ndollars(15_000_000_000, 0),
            15_000_000_000
        );
        // Discount = 99.90% leaves 0.10% of retail.
        assert_eq!(
            effective_per_mtok_ndollars(15_000_000_000, MAX_DISCOUNT_BP),
            15_000_000
        );
    }

    #[test]
    fn format_per_mtok_usd_renders_three_decimals() {
        assert_eq!(format_per_mtok_usd(3_000_000_000), "$3.000");
        assert_eq!(format_per_mtok_usd(2_685_000_000), "$2.685");
        assert_eq!(format_per_mtok_usd(15_000_000), "$0.015");
        assert_eq!(format_per_mtok_usd(0), "$0.000");
    }

    #[test]
    fn effective_rate_summary_renders_in_and_out() {
        let dims = RetailDimensions {
            input_per_mtok_ndollars: 3_000_000_000,
            output_per_mtok_ndollars: 15_000_000_000,
        };
        assert_eq!(
            effective_rate_summary(&dims, 1050),
            "$2.685 in / $13.425 out per Mtok"
        );
        assert_eq!(
            effective_rate_summary(&dims, 0),
            "$3.000 in / $15.000 out per Mtok"
        );
    }
}
