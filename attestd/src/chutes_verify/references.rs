//! Chutes' published TDX measurement references, compiled into the image.
//!
//! The file is the verbatim body of `GET api.chutes.ai/servers/tee/measurements`
//! and must hash to [`PUBLISHED_SHA256`]; a Chutes VM release is admitted only
//! after gm commits the newer file. The current file was fetched 2026-11-09T15:50:10Z.

use std::sync::OnceLock;

use anyhow::{bail, Context, Result};
use dcap_qvl::quote::TDReport10;
use serde::Deserialize;

const PUBLISHED: &[u8] = include_bytes!("../../references/chutes/measurements-2026-11-09.json");
pub const PUBLISHED_SHA256: &str =
    "08609318828cea9d2091d28060530b2ca84c112d6023a0b34d32cbd13e2a61bd";

/// One measured Chutes VM release on one hardware class.
#[derive(Clone, Debug)]
pub struct Reference {
    pub version: String,
    pub name: String,
    mrtd: [u8; 48],
    rtmrs: [[u8; 48]; 4],
    /// NRAS architecture of the GPUs this hardware class carries.
    pub gpu_arch: Option<&'static str>,
    pub gpu_count: usize,
}

#[derive(Deserialize)]
struct Entry {
    version: String,
    name: String,
    mrtd: String,
    runtime_rtmrs: Rtmrs,
    expected_gpus: Vec<String>,
    gpu_count: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "UPPERCASE")]
struct Rtmrs {
    rtmr0: String,
    rtmr1: String,
    rtmr2: String,
    rtmr3: String,
}

/// The compiled references, parsed once.
///
/// # Errors
///
/// Returns an error when the compiled file does not parse.
pub fn published() -> Result<&'static [Reference]> {
    static PARSED: OnceLock<Result<Vec<Reference>, String>> = OnceLock::new();
    PARSED
        .get_or_init(|| parse(PUBLISHED).map_err(|error| format!("{error:#}")))
        .as_deref()
        .map_err(|error| anyhow::anyhow!("compiled Chutes references: {error}"))
}

fn parse(body: &[u8]) -> Result<Vec<Reference>> {
    let entries: Vec<Entry> =
        serde_json::from_slice(body).context("decode measurement references")?;
    entries
        .into_iter()
        .map(|entry| {
            let rtmrs = [
                &entry.runtime_rtmrs.rtmr0,
                &entry.runtime_rtmrs.rtmr1,
                &entry.runtime_rtmrs.rtmr2,
                &entry.runtime_rtmrs.rtmr3,
            ];
            Ok(Reference {
                mrtd: register(&entry.mrtd)?,
                rtmrs: [
                    register(rtmrs[0])?,
                    register(rtmrs[1])?,
                    register(rtmrs[2])?,
                    register(rtmrs[3])?,
                ],
                gpu_arch: gpu_arch(&entry.expected_gpus),
                gpu_count: entry.gpu_count,
                version: entry.version,
                name: entry.name,
            })
        })
        .collect::<Result<_>>()
}

fn register(hex_value: &str) -> Result<[u8; 48]> {
    hex::decode(hex_value)
        .context("decode measurement register")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("measurement register is not 48 bytes"))
}

// NRAS names architectures, Chutes names GPU models; one class carries one model.
fn gpu_arch(expected_gpus: &[String]) -> Option<&'static str> {
    let mut arches = expected_gpus
        .iter()
        .map(|gpu| match gpu.to_ascii_lowercase().as_str() {
            "h100" | "h200" | "h20" => Some("HOPPER"),
            "b200" | "b300" | "pro_6000" | "rtx_pro_6000" => Some("BLACKWELL"),
            _ => None,
        });
    let first = arches.next()??;
    arches.all(|arch| arch == Some(first)).then_some(first)
}

/// The reference whose MRTD and runtime RTMR0-3 all equal the quote's.
///
/// # Errors
///
/// Returns an error when no reference matches; it names which register
/// families did match, so a new Chutes release is told apart from tampering.
pub fn match_td<'a>(references: &'a [Reference], td: &TDReport10) -> Result<&'a Reference> {
    let rtmrs = [td.rt_mr0, td.rt_mr1, td.rt_mr2, td.rt_mr3];
    if let Some(reference) = references
        .iter()
        .find(|reference| reference.mrtd == td.mr_td && reference.rtmrs == rtmrs)
    {
        return Ok(reference);
    }
    if references
        .iter()
        .any(|reference| reference.mrtd == td.mr_td)
    {
        bail!(
            "MRTD {} is published but no entry with it has these runtime RTMR0-3",
            hex::encode(td.mr_td)
        );
    }
    bail!(
        "MRTD {} is not in the published Chutes references",
        hex::encode(td.mr_td)
    )
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test fixtures fail the test")]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    fn td_for(reference: &Reference) -> TDReport10 {
        let quote = include_bytes!("../../tests/fixtures/dcap/tdx_quote");
        let dcap_qvl::quote::Report::TD10(mut td) =
            dcap_qvl::quote::Quote::parse(quote).unwrap().report
        else {
            unreachable!("fixture is a TD 1.0 quote")
        };
        td.mr_td = reference.mrtd;
        [td.rt_mr0, td.rt_mr1, td.rt_mr2, td.rt_mr3] = reference.rtmrs;
        td
    }

    #[test]
    fn compiled_file_is_the_published_payload() {
        assert_eq!(hex::encode(Sha256::digest(PUBLISHED)), PUBLISHED_SHA256);
        let references = published().unwrap();
        assert_eq!(references.len(), 61);
        assert!(references
            .iter()
            .all(|reference| reference.gpu_arch.is_some()));
    }

    #[test]
    fn a_quote_with_published_registers_matches_its_entry() {
        let references = published().unwrap();
        let expected = references.last().unwrap();
        let matched = match_td(references, &td_for(expected)).unwrap();
        assert_eq!(
            (&matched.version, &matched.name),
            (&expected.version, &expected.name)
        );
    }

    fn td_with(mrtd: &str, rtmrs: [&str; 4]) -> TDReport10 {
        let reference = Reference {
            version: String::new(),
            name: String::new(),
            mrtd: register(mrtd).unwrap(),
            rtmrs: rtmrs.map(|value| register(value).unwrap()),
            gpu_arch: None,
            gpu_count: 0,
        };
        td_for(&reference)
    }

    #[test]
    fn a_vm_1_5_0_pro_6000_quote_is_admitted() {
        let td = td_with(
            "261CE538B435E2D0E85FC97E254BC99154C507B7A8E13D59B69F8532384F1D0B\
             FAADFDDF3FCCC6E0A411203840BBEE8D",
            [
                "BACB4ABF7B19ABA4A8307EBC7244706745DE4FA627E669E7F06FD35C3303EEA1\
                 903F58DC143D27B557DA1A986E0E95F6",
                "D3A862FF47357F374FC72C7F02A480A13790D1805E24AAA8DE1F03994256625C\
                 E0F593AE35EA8F0C24D09F7DF36CB0ED",
                "E1DE99043052F3E1AB5A4463D3310B5680E851631ADF10E071B15CBD8B4D664E\
                 A435B0EC33E7F18E908DDA60734056F7",
                "9617BE835BEAC8C62093A9DB424F015F3E12651235D0101C112729E7225B7A70\
                 836A184DEE0B45F28CD190F1871AFE6E",
            ],
        );
        let matched = match_td(published().unwrap(), &td).unwrap();
        assert_eq!(matched.version, "1.5.0");
        assert!(matched.name.starts_with("8xpro_6000"), "{}", matched.name);
        assert_eq!(matched.gpu_arch, Some("BLACKWELL"));
    }

    #[test]
    fn a_vm_release_chutes_withdrew_is_rejected() {
        let td = td_with(
            "DDC6EFCDD2309E10837F8A7F64B71272B7EF003B129460410FE715BDFFFEC38C\
             7C0C1686DDDB2A23D4FD623D145E8455",
            [
                "2864B11878E8129095D62A5DD7C3E3AAE178D3A077606A825617324768F189AD\
                 05AED08376947DF92D6C75865D915CBF",
                "F858ED2AECBA4ECD29084352C6B5C6E403C0BEC89B8C852F90FA5A8CEE796FFA\
                 095518C5CD8B92C25C1856E932A95877",
                "7719F4FDE518994A5DD6767A8B8B87A38168CC0F3480E7498D4ACE99E49319BE\
                 6A7FED26C21AD43310D2D488FC68AB1C",
                "BFAC8BBE97148D00C0BC5DEA273CCD926E2415511F08F5DEDAA96D3C19E824D2\
                 BF01FAE86E8987FF509FD3AD31374A60",
            ],
        );
        let error = match_td(published().unwrap(), &td).unwrap_err();
        assert!(
            error.to_string().contains("not in the published"),
            "{error:#}"
        );
    }

    #[test]
    fn mrtd_off_the_list_fails_closed() {
        let references = published().unwrap();
        let mut td = td_for(&references[0]);
        td.mr_td[0] ^= 1;
        let error = match_td(references, &td).unwrap_err();
        assert!(
            error.to_string().contains("not in the published"),
            "{error:#}"
        );
    }

    #[test]
    fn any_runtime_rtmr_mismatch_fails_closed() {
        let references = published().unwrap();
        for register in 0..4 {
            let mut td = td_for(&references[0]);
            match register {
                0 => td.rt_mr0[47] ^= 1,
                1 => td.rt_mr1[47] ^= 1,
                2 => td.rt_mr2[47] ^= 1,
                _ => td.rt_mr3[47] ^= 1,
            }
            let error = match_td(references, &td).unwrap_err();
            assert!(
                error.to_string().contains("RTMR"),
                "RTMR{register}: {error:#}"
            );
        }
    }

    #[test]
    fn a_boot_time_quote_is_not_a_runtime_match() {
        let references = published().unwrap();
        let mut td = td_for(&references[0]);
        td.rt_mr3 = [0; 48];
        assert!(match_td(references, &td).is_err());
    }

    #[test]
    fn gpu_models_map_to_one_nras_architecture() {
        let names = |list: &[&str]| {
            list.iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(gpu_arch(&names(&["h200"])), Some("HOPPER"));
        assert_eq!(gpu_arch(&names(&["b300"])), Some("BLACKWELL"));
        assert_eq!(gpu_arch(&names(&["h200", "b200"])), None);
        assert_eq!(gpu_arch(&names(&["mi300"])), None);
        assert_eq!(gpu_arch(&[]), None);
    }
}
