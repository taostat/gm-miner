//! The one text table the CLI prints, sized to its own content.
//!
//! Every table here used to carry a hand-picked width per column, and every
//! one of them was picked against a `$3.000` example. Prices now render to
//! whatever precision they need (`pricing::format_usd`), so a cheap model puts
//! `$0.000894999 in / $0.000000894 out per Mtok (+10 more)` in a cell chosen to
//! hold twelve characters — and the columns after it shift off their headers,
//! in exactly the views meant to make cheap models legible. A width measured
//! from the data cannot be outgrown.

use std::fmt::Write as _;

/// Header row, rule, and one line per row, every column as wide as its own
/// widest cell.
///
/// Every column is padded, including the last, so header, rule and each row
/// come out the same length — that equality is the property worth asserting in
/// a test, and asserting it on *every* row is what catches an overflowing
/// cell. A rule-width check against the header alone passes no matter how far
/// the rows overflow, which is how the fixed widths survived as long as they
/// did.
///
/// Widths count Unicode scalars, which is exactly what `{:<width$}` pads by,
/// so the rows stay self-consistent whatever the cells hold. That equals
/// *terminal* columns only for characters one column wide; every cell the CLI
/// puts in a table is ASCII (providers are a fixed enum, model ids are
/// provider API identifiers that must survive URL-path interpolation, and
/// prices are digits and `$./`). `product.json` sets no `pattern` on the model
/// field, so that is a property of the catalog rather than a guarantee of the
/// contract — a wide-glyph slug would misalign the columns after it and
/// nothing worse, which does not earn a `unicode-width` dependency. Revisit if
/// a non-ASCII id ever reaches the catalog.
///
/// Cells beyond `headers.len()` are ignored, and a short row is padded out, so
/// a caller cannot produce a ragged table by miscounting.
///
/// # Preconditions
///
/// **Every cell must be a single line of printable text.** A cell holding a
/// newline breaks one row into several physical lines while the character
/// counts stay uniform, and a tab or an escape sequence advances the cursor by
/// something other than its character count — either way the table renders
/// ragged, or a crafted cell could draw a convincing fake row. Nothing is
/// stripped here, for the same reason nothing measures glyph width: every cell
/// the CLI puts in a table is a provider enum, a generated label, a formatted
/// price, or a model id that has to survive URL-path interpolation, so none of
/// them can carry a control character today. Sanitising would be dead code
/// guarding a case the callers make impossible. If a table ever renders a
/// free-text field — a registry-supplied reason string, say — that field is
/// where the escaping belongs, and this precondition is the reason why.
#[must_use]
pub fn render(headers: &[&str], rows: &[Vec<String>]) -> Vec<String> {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }

    let line = |cells: &mut dyn Iterator<Item = &str>| -> String {
        let mut out = String::new();
        for (i, width) in widths.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            let cell = cells.next().unwrap_or("");
            let _ = write!(out, "{cell:<width$}");
        }
        out
    };

    let mut lines = vec![
        line(&mut headers.iter().copied()),
        "-".repeat(widths.iter().sum::<usize>() + widths.len().saturating_sub(1)),
    ];
    lines.extend(
        rows.iter()
            .map(|row| line(&mut row.iter().map(String::as_str))),
    );
    lines
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::render;

    fn row(cells: &[&str]) -> Vec<String> {
        cells.iter().map(|&c| c.to_owned()).collect()
    }

    /// The invariant every table test should assert: not "the rule matches the
    /// header" — which holds however far a row overflows — but that every
    /// single line is the same width.
    fn assert_uniform(lines: &[String]) {
        let width = lines[0].chars().count();
        for line in lines {
            assert_eq!(
                line.chars().count(),
                width,
                "line is not the table's width:\n{}",
                lines.join("\n")
            );
        }
    }

    #[test]
    fn a_cell_wider_than_its_header_widens_the_column() {
        let lines = render(
            &["MODEL", "COST"],
            &[
                row(&["gpt-5.6", "$0.000894999"]),
                row(&["claude-sonnet-4-6", "$3.000"]),
            ],
        );
        assert_uniform(&lines);
        assert!(lines[2].contains("$0.000894999"), "{lines:?}");
        // The widest cell in each column sets that column, so the short row's
        // last column still starts where the header's does.
        let cost_at = lines[0].find("COST").expect("header names the column");
        assert!(lines[3][cost_at..].starts_with("$3.000"), "{lines:?}");
    }

    #[test]
    fn a_table_with_no_rows_is_still_a_header_and_a_rule() {
        let lines = render(&["MODEL", "COST"], &[]);
        assert_eq!(lines.len(), 2);
        assert_uniform(&lines);
    }

    #[test]
    fn a_short_row_is_padded_rather_than_making_the_table_ragged() {
        let lines = render(&["A", "B", "C"], &[row(&["one"]), row(&["x", "y", "z"])]);
        assert_uniform(&lines);
    }

    #[test]
    fn a_long_row_cannot_push_past_the_last_column() {
        let lines = render(&["A", "B"], &[row(&["x", "y", "ignored"])]);
        assert_uniform(&lines);
        assert!(!lines.join("\n").contains("ignored"));
    }
}
