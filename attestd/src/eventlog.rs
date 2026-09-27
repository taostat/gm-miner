//! TDX CC event log (CCEL) parsing and RTMR replay.
//!
//! The log is in the TCG2 crypto-agile format: one `TCG_PCR_EVENT` header
//! carrying the `Spec ID Event03` structure that lists every digest
//! algorithm and its size, then `TCG_PCR_EVENT2` records until the end of
//! the buffer or the `0xFF` padding of the reserved CCEL area. A record's
//! index is the CC measurement register: 1 to 4 are RTMR0 to RTMR3 (0 is
//! MRTD, which the TDX module measures and no event may extend).
//!
//! Replay starts every RTMR at zero and extends it with each record's
//! SHA-384 digest, `RTMR = SHA-384(RTMR || digest)`, the TDX `TDG.MR.RTMR.EXTEND`
//! rule. `EV_NO_ACTION` records are informational and never extended.

use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest as _, Sha384};

/// A SHA-384 measurement register value.
pub type Register = [u8; 48];

const SPEC_ID_SIGNATURE: &[u8; 16] = b"Spec ID Event03\0";
const EV_NO_ACTION: u32 = 0x0000_0003;
const TPM_ALG_SHA384: u16 = 0x000C;
const SHA1_DIGEST_LEN: usize = 20;
const MAX_EVENTS: usize = 4096;
const MAX_ALGORITHMS: usize = 16;
const PADDING: u32 = u32::MAX;

/// One measured record of the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// RTMR index, 0 to 3.
    pub rtmr: usize,
    /// The TCG event type.
    pub event_type: u32,
    /// The SHA-384 digest extended into the register.
    pub digest: Register,
    /// The event data, for the record only.
    pub data: Vec<u8>,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .with_context(|| format!("event log truncated at byte {}", self.offset))?;
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn peek_u32(&self) -> Option<u32> {
        let bytes = self.bytes.get(self.offset..self.offset.checked_add(4)?)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn at_end(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn rest_is_padding(&self) -> bool {
        self.bytes[self.offset..].iter().all(|byte| *byte == 0xFF)
    }
}

/// Parse a CCEL into its measured records.
///
/// # Errors
///
/// Returns an error for a truncated or malformed log, a header that is not
/// `Spec ID Event03`, a log without SHA-384 digests, a record that lacks
/// one, or a record naming a register other than RTMR0-3.
pub fn parse(log: &[u8]) -> Result<Vec<Event>> {
    let mut cursor = Cursor {
        bytes: log,
        offset: 0,
    };
    let digest_sizes = parse_header(&mut cursor)?;
    let mut events = Vec::new();
    while !cursor.at_end() {
        if cursor.peek_u32() == Some(PADDING) {
            ensure!(
                cursor.rest_is_padding(),
                "event log has data after its 0xFF padding"
            );
            break;
        }
        ensure!(
            events.len() < MAX_EVENTS,
            "event log has more than {MAX_EVENTS} records"
        );
        if let Some(event) = parse_event(&mut cursor, &digest_sizes)? {
            events.push(event);
        }
    }
    Ok(events)
}

/// Replay `events` into the four RTMRs.
#[must_use]
pub fn replay(events: &[Event]) -> [Register; 4] {
    let mut registers = [[0_u8; 48]; 4];
    for event in events {
        let mut hasher = Sha384::new();
        hasher.update(registers[event.rtmr]);
        hasher.update(event.digest);
        registers[event.rtmr] = hasher.finalize().into();
    }
    registers
}

fn parse_header(cursor: &mut Cursor<'_>) -> Result<Vec<(u16, usize)>> {
    let _index = cursor.u32()?;
    let event_type = cursor.u32()?;
    ensure!(
        event_type == EV_NO_ACTION,
        "event log header type is {event_type:#x}, expected EV_NO_ACTION"
    );
    cursor.take(SHA1_DIGEST_LEN)?;
    let size = cursor.u32()? as usize;
    let mut spec = Cursor {
        bytes: cursor.take(size)?,
        offset: 0,
    };
    ensure!(
        spec.take(16)? == SPEC_ID_SIGNATURE,
        "event log header is not Spec ID Event03"
    );
    spec.take(4 + 1 + 1 + 1 + 1)?;
    let count = spec.u32()? as usize;
    ensure!(
        (1..=MAX_ALGORITHMS).contains(&count),
        "event log lists {count} digest algorithms"
    );
    let mut sizes = Vec::with_capacity(count);
    for _ in 0..count {
        let algorithm = spec.u16()?;
        let size = spec.u16()? as usize;
        sizes.push((algorithm, size));
    }
    ensure!(
        sizes.contains(&(TPM_ALG_SHA384, 48)),
        "event log does not carry SHA-384 digests"
    );
    Ok(sizes)
}

fn parse_event(cursor: &mut Cursor<'_>, digest_sizes: &[(u16, usize)]) -> Result<Option<Event>> {
    let index = cursor.u32()?;
    let event_type = cursor.u32()?;
    let count = cursor.u32()? as usize;
    ensure!(
        count <= digest_sizes.len(),
        "event record has {count} digests"
    );
    let mut sha384 = None;
    for _ in 0..count {
        let algorithm = cursor.u16()?;
        let size = digest_sizes
            .iter()
            .find(|(listed, _)| *listed == algorithm)
            .map(|(_, size)| *size)
            .with_context(|| format!("event record uses unlisted algorithm {algorithm:#x}"))?;
        let digest = cursor.take(size)?;
        if algorithm == TPM_ALG_SHA384 {
            ensure!(sha384.is_none(), "event record repeats its SHA-384 digest");
            sha384 = Some(digest);
        }
    }
    let data_len = cursor.u32()? as usize;
    let data = cursor.take(data_len)?.to_vec();
    if event_type == EV_NO_ACTION {
        return Ok(None);
    }
    let rtmr = match index {
        1..=4 => index as usize - 1,
        _ => bail!("event record extends measurement register {index}, not an RTMR"),
    };
    let digest = sha384
        .context("event record has no SHA-384 digest")?
        .try_into()
        .context("SHA-384 digest is not 48 bytes")?;
    Ok(Some(Event {
        rtmr,
        event_type,
        digest,
        data,
    }))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "fixture decoding fails the test")]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    fn fixture_log() -> Vec<u8> {
        let payload: serde_json::Value =
            serde_json::from_slice(include_bytes!("../tests/fixtures/kubetee/attestation.json"))
                .unwrap();
        STANDARD
            .decode(payload["cc_eventlog"].as_str().unwrap())
            .unwrap()
    }

    /// Byte offset of the first record after the header.
    fn first_record(log: &[u8]) -> usize {
        let header_data = u32::from_le_bytes(log[28..32].try_into().unwrap()) as usize;
        32 + header_data
    }

    #[test]
    fn the_live_log_parses_into_rtmr_records() {
        let events = parse(&fixture_log()).unwrap();
        assert_eq!(events.len(), 22);
        assert!(events.iter().all(|event| event.rtmr <= 2));
        assert!(events.iter().any(|event| event
            .data
            .windows(25)
            .any(|w| w == b"LOADED_IMAGE::LoadOptions")));
    }

    #[test]
    fn replay_extends_from_zero_in_order() {
        let first = Event {
            rtmr: 1,
            event_type: 1,
            digest: [1; 48],
            data: Vec::new(),
        };
        let second = Event {
            digest: [2; 48],
            ..first.clone()
        };
        let registers = replay(&[first, second]);
        let once: Register = Sha384::digest([[0_u8; 48], [1; 48]].concat()).into();
        let twice: Register = Sha384::digest([once, [2; 48]].concat()).into();
        assert_eq!(registers[1], twice);
        assert_eq!(registers[0], [0; 48]);
        assert_eq!(registers[3], [0; 48]);
    }

    #[test]
    fn a_flipped_digest_changes_the_replay() {
        let log = fixture_log();
        let mut tampered = log.clone();
        let digest_offset = first_record(&log) + 12 + 2;
        tampered[digest_offset] ^= 1;
        assert_ne!(
            replay(&parse(&log).unwrap()),
            replay(&parse(&tampered).unwrap())
        );
    }

    #[test]
    fn truncation_fails_closed() {
        let log = fixture_log();
        let cut = first_record(&log) + 20;
        let error = parse(&log[..cut]).unwrap_err();
        assert!(error.to_string().contains("truncated"), "{error:#}");
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn data_after_padding_fails_closed() {
        let mut log = fixture_log();
        log.extend_from_slice(&[0xFF; 8]);
        log.push(0);
        let error = parse(&log).unwrap_err();
        assert!(error.to_string().contains("padding"), "{error:#}");
    }

    #[test]
    fn a_record_outside_rtmr0_to_3_fails_closed() {
        let mut log = fixture_log();
        let start = first_record(&log);
        log[start..start + 4].copy_from_slice(&5_u32.to_le_bytes());
        let error = parse(&log).unwrap_err();
        assert!(error.to_string().contains("not an RTMR"), "{error:#}");
    }

    #[test]
    fn a_log_without_sha384_fails_closed() {
        let mut log = fixture_log();
        let first_algorithm = 32 + 16 + 8 + 4;
        assert_eq!(log[first_algorithm..first_algorithm + 2], [0x0C, 0x00]);
        log[first_algorithm] = 0x0B;
        let error = parse(&log).unwrap_err();
        assert!(error.to_string().contains("SHA-384"), "{error:#}");
    }

    #[test]
    fn a_header_that_is_not_spec_id_event03_fails_closed() {
        let mut log = fixture_log();
        log[32] = b'X';
        let error = parse(&log).unwrap_err();
        assert!(error.to_string().contains("Spec ID"), "{error:#}");
    }
}
