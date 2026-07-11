//! `gmcli pricing` — how the miner's offers rank against the eligible field.

use anyhow::{Context as _, Result};

use gm_miner_cli::{
    client::RegistryClient,
    network::Network,
    pricing::{format_discount_pct, format_per_mtok_usd},
    types::{PricingCompetitiveness, ProductCompetitiveness},
};

use crate::commands::me_error;

const PRICING_PATH: &str = "/miners/me/pricing-competitiveness";

/// `gmcli pricing` — rank each offer against the field of eligible competitors.
///
/// The registry ranks on the exact scalar the gateway routes on (the cost of a
/// 1M-input + 1M-output reference request at the miner's effective price), so
/// rank 1 here is the offer the router reaches for first. The view is
/// identity-safe: aggregates over the field, never a rival's hotkey.
pub(crate) async fn cmd_pricing(client: &mut RegistryClient) -> Result<()> {
    let network = client.config.resolved_network();
    let resp = client
        .get(PRICING_PATH)
        .await
        .with_context(|| format!("GET {PRICING_PATH}"))?;

    let status_code = resp.status();
    if !status_code.is_success() {
        return Err(me_error(network, status_code));
    }
    let body: PricingCompetitiveness = resp.json().await.context("parse pricing response")?;

    println!("{}", render_pricing(network, &body.products).join("\n"));
    Ok(())
}

fn render_pricing(network: Network, products: &[ProductCompetitiveness]) -> Vec<String> {
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
    lines.extend(advice_lines(&yours));
    lines
}

fn rank_table(yours: &[&ProductCompetitiveness]) -> Vec<String> {
    let mut lines = vec![
        format!(
            "{:<12} {:<32} {:<12} {:<10} {:<12} {:<12} {:<12}",
            "PROVIDER", "MODEL", "YOUR RANK", "DISCOUNT", "YOUR COST", "BEST", "MEDIAN"
        ),
        "-".repeat(105),
    ];
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
            .map_or_else(|| "—".to_owned(), format_per_mtok_usd);
        lines.push(format!(
            "{:<12} {:<32} {:<12} {:<10} {:<12} {:<12} {:<12}",
            p.provider,
            p.model,
            rank,
            discount,
            your_cost,
            format_per_mtok_usd(p.best_cost_ndollars),
            format_per_mtok_usd(p.median_cost_ndollars),
        ));
    }
    lines
}

/// Products the field serves and this miner does not — the unsold nudge.
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
            format_per_mtok_usd(p.best_cost_ndollars),
            format_per_mtok_usd(p.median_cost_ndollars),
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
        if yours.is_empty() {
            return Vec::new();
        }
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
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::*;

    fn products(value: serde_json::Value) -> Vec<ProductCompetitiveness> {
        serde_json::from_value(value).expect("decode competitiveness")
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
    }
}
