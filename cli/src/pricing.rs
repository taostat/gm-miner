//! Discount/price conversion, plus the `gmcli pricing` competitiveness view.
//! All arithmetic is integer-only — money is nano-dollars (1 nUSD = 10⁻⁹ USD),
//! never a float.

use std::fmt::Write as _;

use anyhow::Result;

use crate::network::Network;
use crate::types::{ProductCompetitiveness, RetailDimensions};

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

/// Render an ndollar amount as dollars with 3 decimal places (e.g.
/// `2_685_000_000 → "$2.685"`). One nano-dollar is `10^-9` USD; a tenth of a
/// cent is the resolution the operator actually cares about.
#[must_use]
pub fn format_usd(ndollars: u64) -> String {
    let dollars = ndollars / 1_000_000_000;
    let millis = (ndollars % 1_000_000_000) / 1_000_000;
    format!("${dollars}.{millis:03}")
}

#[must_use]
pub fn format_per_mtok_usd(ndollars: u64) -> String {
    format_usd(ndollars)
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

/// The `gmcli pricing` view: how each of the miner's offers ranks against the
/// field, plus the products only others serve.
#[must_use]
pub fn render_pricing(network: Network, products: &[ProductCompetitiveness]) -> Vec<String> {
    let (yours, unsold): (Vec<_>, Vec<_>) = products.iter().partition(|p| p.offered_by_you);

    let mut lines = vec![
        format!("Pricing competitiveness ({network})"),
        "Buyers route to the cheapest eligible offer. Cost is one reference request:".to_owned(),
        "1M input tokens + 1M output tokens at your effective price.".to_owned(),
        String::new(),
    ];

    if yours.is_empty() {
        lines.push("You have no eligible offers to rank.".to_owned());
    } else {
        lines.extend(rank_table(&yours));
    }
    if !unsold.is_empty() {
        lines.extend(unsold_lines(&unsold));
    }
    if !yours.is_empty() {
        lines.extend(advice_lines(&yours));
    }
    lines
}

const RANK_COLUMNS: [(&str, usize); 7] = [
    ("PROVIDER", 12),
    ("MODEL", 32),
    ("YOUR RANK", 12),
    ("DISCOUNT", 10),
    ("YOUR COST", 12),
    ("BEST", 12),
    ("MEDIAN", 12),
];

fn rank_row(cells: &[String; 7]) -> String {
    let mut row = String::new();
    for (i, ((_, width), cell)) in RANK_COLUMNS.iter().zip(cells).enumerate() {
        if i > 0 {
            row.push(' ');
        }
        let _ = write!(row, "{cell:<width$}");
    }
    row
}

fn rank_rule() -> String {
    let cells: usize = RANK_COLUMNS.iter().map(|&(_, width)| width).sum();
    "-".repeat(cells + RANK_COLUMNS.len() - 1)
}

fn rank_table(yours: &[&ProductCompetitiveness]) -> Vec<String> {
    let header = RANK_COLUMNS.map(|(name, _)| name.to_owned());
    let mut lines = vec![rank_row(&header), rank_rule()];
    for p in yours {
        let rank = p.your_rank.map_or_else(
            || "—".to_owned(),
            |rank| format!("{rank} of {}", p.competitor_count),
        );
        let discount = p.your_discount_bp.map_or_else(
            || "—".to_owned(),
            |bp| format!("{}%", format_discount_pct(bp)),
        );
        let your_cost = p
            .your_cost_ndollars
            .map_or_else(|| "—".to_owned(), format_usd);
        lines.push(rank_row(&[
            p.provider.clone(),
            p.model.clone(),
            rank,
            discount,
            your_cost,
            format_usd(p.best_cost_ndollars),
            format_usd(p.median_cost_ndollars),
        ]));
    }
    lines
}

fn unsold_lines(unsold: &[&ProductCompetitiveness]) -> Vec<String> {
    let mut lines = vec![
        String::new(),
        format!("Offered by others, not by you ({}):", unsold.len()),
    ];
    for p in unsold {
        lines.push(format!(
            "  {}/{}: {} eligible offer(s), best {}, median {}",
            p.provider,
            p.model,
            p.competitor_count,
            format_usd(p.best_cost_ndollars),
            format_usd(p.median_cost_ndollars),
        ));
    }
    lines.push(
        "  Declare one with `gmcli declare-product --provider <p> --model <m> \
         --discount-pct <pct>`."
            .to_owned(),
    );
    lines
}

/// Name the offers the router passes over on price, and what to do about them.
///
/// Only an offer *strictly* dearer than the field's best loses a route on
/// price; rank 1 is shared by every miner that ties the best cost, so a rank-1
/// offer is never called out here.
fn advice_lines(yours: &[&ProductCompetitiveness]) -> Vec<String> {
    let outranked: Vec<_> = yours
        .iter()
        .filter(|p| p.your_rank.is_some_and(|rank| rank > 1))
        .collect();
    if outranked.is_empty() {
        return vec![
            String::new(),
            "You are at the cheapest cost on every product you offer.".to_owned(),
        ];
    }

    let mut lines = vec![
        String::new(),
        format!(
            "{} offer(s) are dearer than the cheapest in their field — the router reaches",
            outranked.len()
        ),
        "for those competitors first. Raise your discount to close the gap:".to_owned(),
    ];
    for p in outranked {
        lines.push(format!(
            "  gmcli declare-product --provider {} --model {} --discount-pct <above {}>",
            p.provider,
            p.model,
            p.your_discount_bp
                .map_or_else(|| "current".to_owned(), format_discount_pct),
        ));
    }
    lines
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests intentionally panic on unexpected values"
)]
mod tests {
    use super::{
        effective_per_mtok_ndollars, effective_rate_summary, format_discount_pct, format_usd,
        parse_discount_pct, rank_row, rank_rule, render_pricing, Network, ProductCompetitiveness,
        MAX_DISCOUNT_BP, RANK_COLUMNS,
    };
    use crate::types::RetailDimensions;

    fn products(value: serde_json::Value) -> Vec<ProductCompetitiveness> {
        serde_json::from_value(value).expect("decode competitiveness")
    }

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
    fn format_usd_renders_three_decimals() {
        assert_eq!(format_usd(3_000_000_000), "$3.000");
        assert_eq!(format_usd(2_685_000_000), "$2.685");
        assert_eq!(format_usd(15_000_000), "$0.015");
        assert_eq!(format_usd(0), "$0.000");
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

    #[test]
    fn the_rank_rule_is_exactly_as_wide_as_a_row() {
        let row = rank_row(&RANK_COLUMNS.map(|(name, _)| name.to_owned()));
        assert_eq!(rank_rule().chars().count(), row.chars().count());
    }

    #[test]
    fn an_outranked_offer_is_named_with_the_command_that_fixes_it() {
        let rendered = render_pricing(
            Network::Mainnet,
            &products(serde_json::json!([{
                "provider": "anthropic", "model": "claude-sonnet-4-6",
                "competitor_count": 5,
                "best_cost_ndollars": 16_200_000_000_u64,
                "median_cost_ndollars": 18_000_000_000_u64,
                "offered_by_you": true,
                "your_cost_ndollars": 18_000_000_000_u64,
                "your_discount_bp": 500,
                "your_rank": 3,
            }])),
        )
        .join("\n");

        assert!(rendered.contains("3 of 5"));
        assert!(rendered.contains("$18.000"));
        assert!(rendered.contains("$16.200"));
        assert!(rendered.contains("1 offer(s) are dearer"));
        assert!(rendered
            .contains("gmcli declare-product --provider anthropic --model claude-sonnet-4-6"));
        assert!(rendered.contains("<above 5>"));
    }

    #[test]
    fn the_cheapest_miner_is_told_it_is_cheapest_and_gets_no_advice() {
        let rendered = render_pricing(
            Network::Mainnet,
            &products(serde_json::json!([{
                "provider": "openai", "model": "gpt-5.6",
                "competitor_count": 3,
                "best_cost_ndollars": 12_000_000_000_u64,
                "median_cost_ndollars": 13_500_000_000_u64,
                "offered_by_you": true,
                "your_cost_ndollars": 12_000_000_000_u64,
                "your_discount_bp": 1_000,
                "your_rank": 1,
            }])),
        )
        .join("\n");

        assert!(rendered.contains("1 of 3"));
        assert!(rendered.contains("cheapest cost on every product you offer"));
        assert!(!rendered.contains("declare-product"));
    }

    #[test]
    fn a_product_only_others_serve_becomes_a_nudge() {
        let rendered = render_pricing(
            Network::Mainnet,
            &products(serde_json::json!([{
                "provider": "gemini", "model": "gemini-3-pro",
                "competitor_count": 4,
                "best_cost_ndollars": 8_100_000_000_u64,
                "median_cost_ndollars": 9_000_000_000_u64,
                "offered_by_you": false,
                "your_cost_ndollars": null,
                "your_discount_bp": null,
                "your_rank": null,
            }])),
        )
        .join("\n");

        assert!(rendered.contains("You have no eligible offers to rank."));
        assert!(rendered.contains("Offered by others, not by you (1):"));
        assert!(rendered.contains("gemini/gemini-3-pro: 4 eligible offer(s), best $8.100"));
        assert!(!rendered.contains("cheapest cost on every product"));
    }
}
