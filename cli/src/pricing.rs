//! Discount/price conversion, plus the `gmcli pricing` competitiveness view.
//! All arithmetic is integer-only — money is nano-dollars (1 nUSD = 10⁻⁹ USD),
//! never a float.
//!
//! Prices are a *vector*, not a pair: a product prices input and output plus
//! up to ten further dimensions (prompt cache, audio, image, long context). A
//! percent discount is the ergonomic way to express an offer, and
//! [`effective_dimensions`] resolves it into the absolute per-dimension
//! figures the miner is shown before declaring. Shown, not agreed: the wire
//! carries the percentage, and the registry re-resolves it against its own
//! retail. [`PRICE_DIMENSIONS`] is the one list of dimensions the arithmetic
//! and the rendering both walk.

use anyhow::Result;

use crate::network::Network;
use crate::table;
use crate::types::{ProductCompetitiveness, RetailDimensions};

/// Inclusive upper bound on `discount_bp`. The registry's pydantic schema
/// pins the same value (`registry/.../schemas.py::ProductDeclarationRequest`);
/// kept in sync by the API-shape pin in the PR plan §3.1.
pub const MAX_DISCOUNT_BP: u32 = 9_990;

/// clap `value_parser` for `--discount-pct`.
///
/// Parses a percent string with up to two decimal places into an integer
/// basis-point value without floating-point arithmetic. The result is both
/// what the miner is asked to confirm and what the request body carries;
/// [`effective_dimensions`] resolves it against the product's retail vector
/// only so the figures can be shown alongside.
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

/// One priced dimension of a [`RetailDimensions`] vector: the label the CLI
/// prints, whether it is one of the two anchors, and the accessors that read
/// and write it.
///
/// [`PRICE_DIMENSIONS`] is the single list of dimensions the CLI knows about,
/// so the vector arithmetic and every rendering of it cannot drift apart.
struct PriceDimension {
    label: &'static str,
    /// True for input and output — the two dimensions every product prices and
    /// the pair the summary line carries. The rest render only when priced.
    anchor: bool,
    get: fn(&RetailDimensions) -> Option<u64>,
    set: fn(&mut RetailDimensions, u64),
}

/// Every *price* dimension, in the order the CLI prints them.
///
/// `long_context_threshold_tokens` is deliberately absent: it is a token
/// count, not a price, so discounting it would be nonsense — it rides through
/// [`effective_dimensions`] untouched.
const PRICE_DIMENSIONS: [PriceDimension; 12] = [
    PriceDimension {
        label: "input",
        anchor: true,
        get: |d| Some(d.input_per_mtok_ndollars),
        set: |d, v| d.input_per_mtok_ndollars = v,
    },
    PriceDimension {
        label: "output",
        anchor: true,
        get: |d| Some(d.output_per_mtok_ndollars),
        set: |d, v| d.output_per_mtok_ndollars = v,
    },
    PriceDimension {
        label: "cache read",
        anchor: false,
        get: |d| d.cache_read_per_mtok_ndollars,
        set: |d, v| d.cache_read_per_mtok_ndollars = Some(v),
    },
    PriceDimension {
        label: "cache write 5m",
        anchor: false,
        get: |d| d.cache_write_5m_per_mtok_ndollars,
        set: |d, v| d.cache_write_5m_per_mtok_ndollars = Some(v),
    },
    PriceDimension {
        label: "cache write 1h",
        anchor: false,
        get: |d| d.cache_write_1h_per_mtok_ndollars,
        set: |d, v| d.cache_write_1h_per_mtok_ndollars = Some(v),
    },
    PriceDimension {
        label: "audio input",
        anchor: false,
        get: |d| d.audio_input_per_mtok_ndollars,
        set: |d, v| d.audio_input_per_mtok_ndollars = Some(v),
    },
    PriceDimension {
        label: "audio output",
        anchor: false,
        get: |d| d.audio_output_per_mtok_ndollars,
        set: |d, v| d.audio_output_per_mtok_ndollars = Some(v),
    },
    PriceDimension {
        label: "image input",
        anchor: false,
        get: |d| d.image_input_per_mtok_ndollars,
        set: |d, v| d.image_input_per_mtok_ndollars = Some(v),
    },
    PriceDimension {
        label: "image output",
        anchor: false,
        get: |d| d.image_output_per_mtok_ndollars,
        set: |d, v| d.image_output_per_mtok_ndollars = Some(v),
    },
    PriceDimension {
        label: "cache storage/hr",
        anchor: false,
        get: |d| d.cache_storage_per_mtok_hour_ndollars,
        set: |d, v| d.cache_storage_per_mtok_hour_ndollars = Some(v),
    },
    PriceDimension {
        label: "long-ctx input",
        anchor: false,
        get: |d| d.long_context_input_per_mtok_ndollars,
        set: |d, v| d.long_context_input_per_mtok_ndollars = Some(v),
    },
    PriceDimension {
        label: "long-ctx output",
        anchor: false,
        get: |d| d.long_context_output_per_mtok_ndollars,
        set: |d, v| d.long_context_output_per_mtok_ndollars = Some(v),
    },
];

/// Resolve a percentage discount into the absolute per-dimension vector the
/// miner is actually paid on.
///
/// Every priced dimension gets the same
/// [`effective_per_mtok_ndollars`] floor; a dimension the product does not
/// price stays unpriced rather than becoming a zero, and
/// `long_context_threshold_tokens` is copied verbatim because it is a token
/// count and not money.
///
/// This is what `declare-product` shows the miner before it sends, so a
/// percentage does not have to be priced in the head. It is *not* what the
/// miner agrees to: the request body carries `discount_bp` alone, and the
/// registry re-resolves the vector against its own retail when it records the
/// offer. `commands::products::sent_as_lines` says so in the output and
/// explains what would have to change for these figures to be the commitment.
#[must_use]
pub fn effective_dimensions(retail: &RetailDimensions, discount_bp: u32) -> RetailDimensions {
    let mut effective = retail.clone();
    for dim in &PRICE_DIMENSIONS {
        if let Some(value) = (dim.get)(retail) {
            (dim.set)(
                &mut effective,
                effective_per_mtok_ndollars(value, discount_bp),
            );
        }
    }
    effective
}

/// Render an ndollar amount *exactly*, at whatever precision the value itself
/// needs (e.g. `2_685_000_000 → "$2.685"`, `999_999 → "$0.000999999"`).
///
/// The one money formatter: every price the CLI prints goes through here.
/// There is deliberately no shorter variant to reach for. Three decimal places
/// look like enough for a whole-request cost right up until the model is a
/// cheap one — a reference request against `chutes` is genuinely sub-milli-
/// dollar — and then two distinct competitor costs render identically, or a
/// real cost renders as free, in `gmcli pricing`, the one view whose entire
/// job is deciding what to charge against the field.
///
/// So precision comes from the amount's own significant digits, never from a
/// fixed width or a tier boundary: a tiered formatter picks a width and
/// truncates everything below it (`1_999_999` → `$0.001`), which shows the
/// miner *less* than the true figure. Nano-dollars are the unit's floor, so
/// nine places is always exact; trailing zeroes then trim back to a minimum of
/// three, because `$3.000` reads as a price and `$3.` does not.
///
/// Integer arithmetic throughout — the fraction is a remainder and a string,
/// never a float.
#[must_use]
pub fn format_usd(ndollars: u64) -> String {
    let dollars = ndollars / 1_000_000_000;
    let mut fraction = format!("{:09}", ndollars % 1_000_000_000);
    while fraction.len() > 3 && fraction.ends_with('0') {
        fraction.pop();
    }
    format!("${dollars}.{fraction}")
}

/// One-line summary of the per-Mtok rate the miner will receive on a
/// product, given retail dimensions and a discount. Shared between
/// the single-product declaration output and the fan-out summary so
/// every site renders the same shape.
///
/// The two anchors only: they are what routing is decided on, and they are the
/// pair every product prices. When the product prices more, the count of the
/// rest is appended so the miner knows to look for
/// [`extra_dimension_lines`] rather than reading the line as the whole deal.
#[must_use]
pub fn effective_rate_summary(retail: &RetailDimensions, discount_bp: u32) -> String {
    let effective = effective_dimensions(retail, discount_bp);
    let summary = format!(
        "{} in / {} out per Mtok",
        format_usd(effective.input_per_mtok_ndollars),
        format_usd(effective.output_per_mtok_ndollars)
    );
    match extra_dimension_count(retail) {
        0 => summary,
        n => format!("{summary} (+{n} more)"),
    }
}

/// How many dimensions beyond input and output this product prices.
#[must_use]
pub fn extra_dimension_count(retail: &RetailDimensions) -> usize {
    PRICE_DIMENSIONS
        .iter()
        .filter(|dim| !dim.anchor && (dim.get)(retail).is_some())
        .count()
}

/// Indented `retail → you receive` rows for every dimension priced beyond the
/// two anchors, in table order.
///
/// Empty for a product that prices only input and output — the common case,
/// and the reason a caller can print this unconditionally without burying a
/// two-dimension product under ten lines of "not priced".
#[must_use]
pub fn extra_dimension_lines(retail: &RetailDimensions, discount_bp: u32) -> Vec<String> {
    let effective = effective_dimensions(retail, discount_bp);
    let rows: Vec<_> = PRICE_DIMENSIONS
        .iter()
        .filter(|dim| !dim.anchor)
        .filter_map(|dim| {
            let priced = (dim.get)(retail)?;
            let received = (dim.get)(&effective)?;
            Some((dim.label, priced, received))
        })
        .collect();
    if rows.is_empty() {
        return Vec::new();
    }

    let label_width = rows
        .iter()
        .map(|(label, ..)| label.len())
        .max()
        .unwrap_or(0);
    let price_width = rows
        .iter()
        .map(|&(_, priced, _)| format_usd(priced).len())
        .max()
        .unwrap_or(0);
    let mut lines: Vec<String> = rows
        .iter()
        .map(|&(label, priced, received)| {
            format!(
                "      {label:<label_width$}  {:>price_width$} → {}",
                format_usd(priced),
                format_usd(received),
            )
        })
        .collect();
    if let Some(threshold) = long_context_note(retail) {
        lines.push(threshold);
    }
    lines
}

/// The token count the long-context rows are the price *above*, when the
/// product prices a long-context tier at all. Without it those two rows are
/// two unexplained numbers.
fn long_context_note(retail: &RetailDimensions) -> Option<String> {
    let threshold = retail.long_context_threshold_tokens?;
    let prices_long_context = retail.long_context_input_per_mtok_ndollars.is_some()
        || retail.long_context_output_per_mtok_ndollars.is_some();
    if !prices_long_context {
        return None;
    }
    Some(format!(
        "      long-ctx rates apply above {threshold} input tokens"
    ))
}

/// The `gmcli pricing` view: how each of the miner's offers ranks against the
/// field, plus the products only others serve.
#[must_use]
pub fn render_pricing(network: Network, products: &[ProductCompetitiveness]) -> Vec<String> {
    let (yours, rest): (Vec<_>, Vec<_>) = products.iter().partition(|p| p.offered_by_you);
    // Absent from the ranked field for two very different reasons: declared and
    // broken (fix it) vs never declared (declare it).
    let (broken, unsold): (Vec<_>, Vec<_>) = rest.iter().partition(|p| p.declared_by_you);

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
    if !broken.is_empty() {
        lines.extend(broken_lines(&broken));
    }
    if !unsold.is_empty() {
        lines.extend(unsold_lines(&unsold));
    }
    if !yours.is_empty() {
        lines.extend(advice_lines(&yours));
    }
    lines
}

const RANK_HEADERS: [&str; 7] = [
    "PROVIDER",
    "MODEL",
    "YOUR RANK",
    "DISCOUNT",
    "YOUR COST",
    "BEST",
    "MEDIAN",
];

/// The rank table, sized to its content by [`table::render`].
///
/// The three cost columns held 12 characters, which was ample while
/// [`format_usd`] truncated at three decimal places. It no longer does — a
/// cheap model's cost is `$0.000894999` — so a fixed width here would push
/// `BEST` and `MEDIAN` off their headers in the view whose entire job is
/// comparing those numbers.
fn rank_table(yours: &[&ProductCompetitiveness]) -> Vec<String> {
    let rows: Vec<Vec<String>> = yours
        .iter()
        .map(|p| {
            vec![
                p.provider.clone(),
                p.model.clone(),
                p.your_rank.map_or_else(
                    || "—".to_owned(),
                    |rank| format!("{rank} of {}", p.competitor_count),
                ),
                p.your_discount_bp.map_or_else(
                    || "—".to_owned(),
                    |bp| format!("{}%", format_discount_pct(bp)),
                ),
                p.your_cost_ndollars
                    .map_or_else(|| "—".to_owned(), format_usd),
                format_usd(p.best_cost_ndollars),
                format_usd(p.median_cost_ndollars),
            ]
        })
        .collect();
    table::render(&RANK_HEADERS, &rows)
}

fn field_line(p: &ProductCompetitiveness) -> String {
    format!(
        "  {}/{}: {} eligible offer(s), best {}, median {}",
        p.provider,
        p.model,
        p.competitor_count,
        format_usd(p.best_cost_ndollars),
        format_usd(p.median_cost_ndollars),
    )
}

/// Products the caller declared but that are not in the eligible field.
///
/// It already ran `declare-product`; the offer is broken, not missing, so the
/// fix is upstream and `gmcli status` is where the reason lives.
fn broken_lines(broken: &[&ProductCompetitiveness]) -> Vec<String> {
    let mut lines = vec![
        String::new(),
        format!(
            "Declared by you but not eligible — earning nothing ({}):",
            broken.len()
        ),
    ];
    lines.extend(broken.iter().copied().map(field_line));
    lines.push("  Run `gmcli status` for the reason and the fix.".to_owned());
    lines
}

fn unsold_lines(unsold: &[&ProductCompetitiveness]) -> Vec<String> {
    let mut lines = vec![
        String::new(),
        format!("Offered by others, not by you ({}):", unsold.len()),
    ];
    lines.extend(unsold.iter().copied().map(field_line));
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
        effective_dimensions, effective_per_mtok_ndollars, effective_rate_summary,
        extra_dimension_count, extra_dimension_lines, format_discount_pct, format_usd,
        parse_discount_pct, rank_table, render_pricing, Network, ProductCompetitiveness,
        MAX_DISCOUNT_BP, PRICE_DIMENSIONS,
    };
    use crate::types::RetailDimensions;

    /// A vector that prices every dimension, so a test can assert on all twelve at
    /// once. The audio prices are deliberately not multiples of 10 000 — the
    /// floor has to bite somewhere.
    fn full_vector() -> RetailDimensions {
        RetailDimensions {
            input_per_mtok_ndollars: 3_000_000_000,
            output_per_mtok_ndollars: 15_000_000_000,
            cache_read_per_mtok_ndollars: Some(300_000_000),
            cache_write_5m_per_mtok_ndollars: Some(3_750_000_000),
            cache_write_1h_per_mtok_ndollars: Some(6_000_000_000),
            audio_input_per_mtok_ndollars: Some(100_000_001),
            audio_output_per_mtok_ndollars: Some(200_000_003),
            image_input_per_mtok_ndollars: Some(500_000_007),
            image_output_per_mtok_ndollars: Some(60_000_000_000),
            cache_storage_per_mtok_hour_ndollars: Some(50_000_000),
            long_context_threshold_tokens: Some(200_000),
            long_context_input_per_mtok_ndollars: Some(6_000_000_000),
            long_context_output_per_mtok_ndollars: Some(22_500_000_000),
        }
    }

    /// Every dimension of `dims` as `(name, value)`, written out by hand.
    ///
    /// The point is that it does *not* go through `PRICE_DIMENSIONS`: a
    /// dimension added to [`RetailDimensions`] but never wired into that table
    /// would keep its retail value through a discount, and a check built on
    /// the same table could not see it.
    fn all_prices(dims: &RetailDimensions) -> Vec<(&'static str, Option<u64>)> {
        vec![
            ("input", Some(dims.input_per_mtok_ndollars)),
            ("output", Some(dims.output_per_mtok_ndollars)),
            ("cache_read", dims.cache_read_per_mtok_ndollars),
            ("cache_write_5m", dims.cache_write_5m_per_mtok_ndollars),
            ("cache_write_1h", dims.cache_write_1h_per_mtok_ndollars),
            ("audio_input", dims.audio_input_per_mtok_ndollars),
            ("audio_output", dims.audio_output_per_mtok_ndollars),
            ("image_input", dims.image_input_per_mtok_ndollars),
            ("image_output", dims.image_output_per_mtok_ndollars),
            ("cache_storage", dims.cache_storage_per_mtok_hour_ndollars),
            (
                "long_context_input",
                dims.long_context_input_per_mtok_ndollars,
            ),
            (
                "long_context_output",
                dims.long_context_output_per_mtok_ndollars,
            ),
        ]
    }

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
    fn format_usd_keeps_three_decimals_when_three_are_enough() {
        assert_eq!(format_usd(3_000_000_000), "$3.000");
        assert_eq!(format_usd(2_685_000_000), "$2.685");
        assert_eq!(format_usd(15_000_000), "$0.015");
        assert_eq!(format_usd(0), "$0.000");
    }

    #[test]
    fn the_competitiveness_view_does_not_truncate_a_cheap_field() {
        // The regression this guards: YOUR COST / BEST / MEDIAN went through a
        // three-decimal formatter, so on a cheap model a real cost rendered
        // "$0.000" — free — and two distinct rival costs rendered identically,
        // in the one view whose whole job is deciding what to charge.
        let rendered = render_pricing(
            Network::Mainnet,
            &products(serde_json::json!([{
                "provider": "chutes", "model": "a-very-cheap-model",
                "competitor_count": 3,
                "best_cost_ndollars": 999_999_u64,
                "median_cost_ndollars": 1_999_999_u64,
                "offered_by_you": true,
                "your_cost_ndollars": 1_999_998_u64,
                "your_discount_bp": 500,
                "your_rank": 2,
            }])),
        )
        .join("\n");

        assert!(rendered.contains("$0.000999999"), "{rendered}");
        assert!(rendered.contains("$0.001999999"), "{rendered}");
        assert!(rendered.contains("$0.001999998"), "{rendered}");
        // Nothing in a priced column may read as free.
        assert!(!rendered.contains("$0.000 "), "{rendered}");
    }

    #[test]
    fn effective_rate_summary_renders_in_and_out() {
        let dims = RetailDimensions {
            input_per_mtok_ndollars: 3_000_000_000,
            output_per_mtok_ndollars: 15_000_000_000,
            ..Default::default()
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
    fn every_rank_row_is_the_width_of_the_rule_not_just_the_header() {
        // The old test compared the rule against the *header* row only, which
        // holds however far the data rows overflow — that is why the fixed
        // 12-char cost columns survived unnoticed once prices stopped being
        // truncated to three decimals. Assert every line.
        //
        // Calibration matters as much as the assertion. Every non-cost cell
        // below sits comfortably inside the width this table used to hardcode
        // (PROVIDER 12, MODEL 32, YOUR RANK 12, DISCOUNT 10) and every cost
        // cell exceeds the 12 the cost columns had, so the test fails if and
        // only if a cost column is re-capped. A long model id would make it
        // fail for the wrong reason and hide a re-capped cost column.
        assert!(
            format_usd(u64::MAX).len() > 12,
            "the cost values must exceed the width being guarded against"
        );
        let field = products(serde_json::json!([
            {
                "provider": "openai", "model": "gpt-5.6",
                "competitor_count": 3,
                "best_cost_ndollars": 9_999_999_999_999_999_999_u64,
                "median_cost_ndollars": 1_234_567_890_123_456_789_u64,
                "offered_by_you": true,
                "your_cost_ndollars": u64::MAX,
                "your_discount_bp": 500,
                "your_rank": 2,
            },
            {
                "provider": "zai", "model": "glm-5.2",
                "competitor_count": 2,
                "best_cost_ndollars": 3_000_000_000_u64,
                "median_cost_ndollars": 4_000_000_000_u64,
                "offered_by_you": true,
                "your_cost_ndollars": 4_000_000_000_u64,
                "your_discount_bp": 1_000,
                "your_rank": 1,
            },
        ]));
        let lines = rank_table(&field.iter().collect::<Vec<_>>());

        let width = lines[0].chars().count();
        for line in &lines {
            assert_eq!(
                line.chars().count(),
                width,
                "row is not the table's width:\n{}",
                lines.join("\n")
            );
        }

        // Every cost is present in full, and MEDIAN still starts where its
        // header does on both the wide row and the narrow one.
        let rendered = lines.join("\n");
        for expected in [
            "$18446744073.709551615",
            "$9999999999.999999999",
            "$1234567890.123456789",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected}:\n{rendered}"
            );
        }
        let median_at = lines[0].find("MEDIAN").expect("the header names MEDIAN");
        assert!(
            lines[2][median_at..].starts_with("$1234567890.123456789"),
            "{rendered}"
        );
        assert!(lines[3][median_at..].starts_with("$4.000"), "{rendered}");
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

    #[test]
    fn a_declared_but_ineligible_offer_is_not_told_to_declare_itself_again() {
        let rendered = render_pricing(
            Network::Mainnet,
            &products(serde_json::json!([{
                "provider": "anthropic", "model": "claude-sonnet-4-6",
                "competitor_count": 2,
                "best_cost_ndollars": 16_200_000_000_u64,
                "median_cost_ndollars": 18_000_000_000_u64,
                "offered_by_you": false,
                "declared_by_you": true,
                "your_cost_ndollars": null,
                "your_discount_bp": null,
                "your_rank": null,
            }])),
        )
        .join("\n");

        assert!(rendered.contains("Declared by you but not eligible — earning nothing (1):"));
        assert!(rendered.contains("anthropic/claude-sonnet-4-6: 2 eligible offer(s)"));
        assert!(rendered.contains("`gmcli status`"));
        // The bug this guards: it already declared the product. Telling it to
        // declare again sends the miner at the wrong problem.
        assert!(!rendered.contains("Offered by others, not by you"));
        assert!(!rendered.contains("declare-product"));
    }

    // ── the price vector ─────────────────────────────────────────────────

    #[test]
    fn every_price_dimension_is_wired_into_the_table() {
        // A dimension missing from PRICE_DIMENSIONS rides through a discount
        // unchanged. Every price in `full_vector` is distinct and non-zero, so
        // an unchanged value names the field that was forgotten.
        let retail = full_vector();
        let effective = effective_dimensions(&retail, 1050);
        let missed: Vec<_> = all_prices(&retail)
            .into_iter()
            .zip(all_prices(&effective))
            .filter(|((_, before), (_, after))| before == after)
            .map(|((name, _), _)| name)
            .collect();
        assert!(
            missed.is_empty(),
            "not discounted — missing from PRICE_DIMENSIONS: {missed:?}"
        );
        assert_eq!(PRICE_DIMENSIONS.len(), all_prices(&retail).len());
    }

    #[test]
    fn every_dimension_takes_the_same_floor_as_the_gateway() {
        let effective = effective_dimensions(&full_vector(), 1050);
        assert_eq!(effective.input_per_mtok_ndollars, 2_685_000_000);
        assert_eq!(effective.output_per_mtok_ndollars, 13_425_000_000);
        assert_eq!(effective.cache_read_per_mtok_ndollars, Some(268_500_000));
        assert_eq!(
            effective.cache_write_5m_per_mtok_ndollars,
            Some(3_356_250_000)
        );
        assert_eq!(
            effective.cache_write_1h_per_mtok_ndollars,
            Some(5_370_000_000)
        );
        assert_eq!(effective.image_input_per_mtok_ndollars, Some(447_500_006));
        assert_eq!(
            effective.image_output_per_mtok_ndollars,
            Some(53_700_000_000)
        );
        assert_eq!(
            effective.cache_storage_per_mtok_hour_ndollars,
            Some(44_750_000)
        );
        assert_eq!(
            effective.long_context_output_per_mtok_ndollars,
            Some(20_137_500_000)
        );
    }

    #[test]
    fn floor_division_truncates_rather_than_rounding() {
        // 100_000_001 × 8950 / 10_000 = 89_500_000.895 → 89_500_000.
        let effective = effective_dimensions(&full_vector(), 1050);
        assert_eq!(effective.audio_input_per_mtok_ndollars, Some(89_500_000));
        // 200_000_003 × 8950 / 10_000 = 179_000_002.685 → 179_000_002.
        assert_eq!(effective.audio_output_per_mtok_ndollars, Some(179_000_002));
        // 500_000_007 × 8950 / 10_000 = 447_500_006.2665 → 447_500_006.
        assert_eq!(effective.image_input_per_mtok_ndollars, Some(447_500_006));

        // A price the floor eats entirely: 3 ndollars at the cap is 0.003 → 0.
        // The miner is shown the zero they will actually be paid.
        let dust = RetailDimensions {
            input_per_mtok_ndollars: 3,
            output_per_mtok_ndollars: 10_000,
            ..Default::default()
        };
        let effective = effective_dimensions(&dust, MAX_DISCOUNT_BP);
        assert_eq!(effective.input_per_mtok_ndollars, 0);
        assert_eq!(effective.output_per_mtok_ndollars, 10);
    }

    #[test]
    fn a_null_dimension_stays_null_rather_than_becoming_zero() {
        // A model with no prompt cache prices no cache dimension. Resolving it
        // to $0.000 would read as "cache reads are free" — a different offer
        // from "this model has no cache".
        let dims = RetailDimensions {
            input_per_mtok_ndollars: 3_000_000_000,
            output_per_mtok_ndollars: 15_000_000_000,
            cache_read_per_mtok_ndollars: Some(300_000_000),
            ..Default::default()
        };
        let effective = effective_dimensions(&dims, 1050);
        assert_eq!(effective.cache_read_per_mtok_ndollars, Some(268_500_000));
        assert_eq!(effective.cache_write_5m_per_mtok_ndollars, None);
        assert_eq!(effective.audio_input_per_mtok_ndollars, None);
        assert_eq!(effective.long_context_output_per_mtok_ndollars, None);
        assert_eq!(extra_dimension_count(&dims), 1);
    }

    #[test]
    fn a_zero_discount_returns_the_retail_vector_verbatim() {
        let retail = full_vector();
        assert_eq!(
            all_prices(&effective_dimensions(&retail, 0)),
            all_prices(&retail)
        );
    }

    #[test]
    fn the_cap_leaves_a_tenth_of_a_percent_on_every_dimension() {
        let effective = effective_dimensions(&full_vector(), MAX_DISCOUNT_BP);
        assert_eq!(effective.input_per_mtok_ndollars, 3_000_000);
        assert_eq!(effective.output_per_mtok_ndollars, 15_000_000);
        assert_eq!(effective.cache_read_per_mtok_ndollars, Some(300_000));
        assert_eq!(
            effective.long_context_output_per_mtok_ndollars,
            Some(22_500_000)
        );
        assert_eq!(effective.image_output_per_mtok_ndollars, Some(60_000_000));
    }

    #[test]
    fn the_long_context_threshold_is_a_token_count_and_is_never_discounted() {
        // Discounting it would move where the long-context tier starts, which
        // is not a price anyone is declaring.
        for bp in [0, 1050, MAX_DISCOUNT_BP] {
            assert_eq!(
                effective_dimensions(&full_vector(), bp).long_context_threshold_tokens,
                Some(200_000),
                "threshold moved at {bp} bp"
            );
        }
    }

    #[test]
    fn a_partial_vector_decodes_from_what_the_registry_actually_sends() {
        // The registry omits dimensions a model does not price rather than
        // always sending explicit nulls, and may add one this build predates.
        let dims: RetailDimensions = serde_json::from_value(serde_json::json!({
            "input_per_mtok_ndollars": 1_400_000_000_u64,
            "output_per_mtok_ndollars": 4_400_000_000_u64,
            "cache_read_per_mtok_ndollars": null,
            "some_dimension_from_the_future_ndollars": 7,
        }))
        .expect("a partial vector carrying an unknown field still decodes");

        assert_eq!(dims.input_per_mtok_ndollars, 1_400_000_000);
        assert_eq!(dims.cache_read_per_mtok_ndollars, None);
        assert_eq!(dims.cache_write_1h_per_mtok_ndollars, None);
        assert_eq!(extra_dimension_count(&dims), 0);
    }

    #[test]
    fn a_unit_price_below_a_tenth_of_a_cent_keeps_its_digits() {
        // Three decimal places would render every one of these as "$0.000",
        // telling the miner a priced dimension pays nothing.
        assert_eq!(format_usd(3_000_000_000), "$3.000");
        assert_eq!(format_usd(1_000_000), "$0.001");
        assert_eq!(format_usd(100_000), "$0.0001");
        assert_eq!(format_usd(1_000), "$0.000001");
        assert_eq!(format_usd(1), "$0.000000001");
        // Zero is a real answer, not a rounding artefact, so it stays short.
        assert_eq!(format_usd(0), "$0.000");
    }

    #[test]
    fn a_unit_price_is_never_truncated_to_a_convenient_width() {
        // Just above each width a tiered formatter would have chosen. Every
        // one of these has significant digits below that width, and dropping
        // them shows the miner less than they are paid.
        assert_eq!(format_usd(1_999_999), "$0.001999999");
        assert_eq!(format_usd(1_999), "$0.000001999");
        assert_eq!(format_usd(999_999), "$0.000999999");
        assert_eq!(format_usd(999), "$0.000000999");
        assert_eq!(format_usd(1_000_000_001), "$1.000000001");
        assert_eq!(format_usd(3_356_250_000), "$3.35625");
        // Every value round-trips: the rendered digits are the amount.
        for ndollars in [
            0_u64,
            1,
            999,
            1_000,
            1_999,
            999_999,
            1_000_000,
            1_999_999,
            44_750_000,
            268_500_000,
            3_356_250_000,
            15_000_000_000,
            u64::MAX,
        ] {
            let rendered = format_usd(ndollars);
            let (dollars, fraction) = rendered
                .trim_start_matches('$')
                .split_once('.')
                .expect("a rendered price always has a decimal point");
            let scale = 10_u128.pow(9 - u32::try_from(fraction.len()).expect("short fraction"));
            let reconstructed = u128::from(dollars.parse::<u64>().expect("whole dollars"))
                * 1_000_000_000
                + u128::from(fraction.parse::<u64>().expect("fraction digits")) * scale;
            assert_eq!(
                reconstructed,
                u128::from(ndollars),
                "{rendered} is not {ndollars} ndollars"
            );
        }
    }

    #[test]
    fn the_summary_line_names_the_dimensions_it_is_not_showing() {
        // The status table cell has room for the two anchors routing is
        // decided on. Without the count a miner reads that line as the whole
        // offer and never looks for the rest.
        assert_eq!(
            effective_rate_summary(&full_vector(), 1050),
            "$2.685 in / $13.425 out per Mtok (+10 more)"
        );
        let anchors_only = RetailDimensions {
            input_per_mtok_ndollars: 3_000_000_000,
            output_per_mtok_ndollars: 15_000_000_000,
            ..Default::default()
        };
        assert_eq!(
            effective_rate_summary(&anchors_only, 1050),
            "$2.685 in / $13.425 out per Mtok"
        );
        assert!(extra_dimension_lines(&anchors_only, 1050).is_empty());
    }

    #[test]
    fn the_extra_rows_show_retail_beside_what_is_received() {
        let rendered = extra_dimension_lines(&full_vector(), 1050).join("\n");
        // Labels pad to the widest present, prices right-align so the decimal
        // points line up — $22.500 next to $0.300 is otherwise unreadable.
        // Matched to the end of the line rather than by `contains`, so a
        // truncated `$0.268` cannot satisfy an assertion written for $0.2685.
        for expected in [
            "cache read              $0.300 → $0.2685",
            "cache storage/hr        $0.050 → $0.04475",
            "long-ctx output        $22.500 → $20.1375",
            "audio output      $0.200000003 → $0.179000002",
            "image input       $0.500000007 → $0.447500006",
            "image output           $60.000 → $53.700",
        ] {
            assert!(
                rendered.lines().any(|line| line.ends_with(expected)),
                "missing {expected:?} in:\n{rendered}"
            );
        }
        // The anchors are on the summary line; repeating them here would
        // double-count the two dimensions that matter most.
        assert!(!rendered.contains("$3.000 → $2.685"), "{rendered}");
        assert!(rendered.contains("long-ctx rates apply above 200000 input tokens"));
    }

    #[test]
    fn a_threshold_without_long_context_prices_explains_nothing_and_is_dropped() {
        // A threshold with no tier priced against it is a dangling number.
        let dims = RetailDimensions {
            input_per_mtok_ndollars: 3_000_000_000,
            output_per_mtok_ndollars: 15_000_000_000,
            cache_read_per_mtok_ndollars: Some(300_000_000),
            long_context_threshold_tokens: Some(200_000),
            ..Default::default()
        };
        let rendered = extra_dimension_lines(&dims, 1050).join("\n");
        assert!(rendered.contains("cache read"));
        assert!(!rendered.contains("long-ctx"), "{rendered}");
    }
}
