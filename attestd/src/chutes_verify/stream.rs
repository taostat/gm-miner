//! Decrypts a Chutes E2E event stream and releases only authenticated content.
//!
//! Every forwarded chunk is AEAD-authenticated under the stream key derived
//! from the per-request response key. The stream completes only with the
//! instance's encrypted `[DONE]`, preceded by a content-free usage frame with
//! billable counts, and cumulative usage is non-decreasing throughout. Usage is
//! released together with that authenticated `[DONE]`: running usage is
//! stripped from content chunks and the terminal frame is held until then.
//! Plaintext relay events (`usage`, `[DONE]`, `e2e_error`) are not forwarded.

use anyhow::{bail, ensure, Context, Result};
use serde_json::Value;

use crate::chutes_verify::crypto::{ResponseKey, StreamKey};

const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;

pub struct StreamDecryptor {
    response_key: ResponseKey,
    model: &'static str,
    stream_key: Option<StreamKey>,
    pending: Vec<u8>,
    usage_total: u64,
    /// The latest content-free usage frame, released only with `[DONE]`.
    held_usage: Option<String>,
    done: bool,
}

impl StreamDecryptor {
    #[must_use]
    pub fn new(response_key: ResponseKey, model: &'static str) -> Self {
        Self {
            response_key,
            model,
            stream_key: None,
            pending: Vec::new(),
            usage_total: 0,
            held_usage: None,
            done: false,
        }
    }

    /// Consume upstream bytes; return the decrypted SSE bytes they complete.
    ///
    /// # Errors
    ///
    /// Returns an error when the stream must be aborted.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.pending.extend_from_slice(bytes);
        let mut output = Vec::new();
        while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=end).collect();
            let line = std::str::from_utf8(&line).context("upstream event is not UTF-8")?;
            self.relay_event(line.trim_end(), &mut output)?;
        }
        ensure!(
            self.pending.len() <= MAX_LINE_BYTES,
            "upstream event exceeds {MAX_LINE_BYTES} bytes"
        );
        Ok(output)
    }

    /// Check the upstream ended after the encrypted `[DONE]`.
    ///
    /// # Errors
    ///
    /// Returns an error when it did not.
    pub fn finish(&self) -> Result<()> {
        ensure!(
            self.done,
            "upstream stream ended before the encrypted [DONE]"
        );
        Ok(())
    }

    fn relay_event(&mut self, line: &str, output: &mut Vec<u8>) -> Result<()> {
        let Some(data) = line.strip_prefix("data:").map(str::trim_start) else {
            return Ok(());
        };
        if data == "[DONE]" {
            ensure!(
                self.done,
                "relay sent a plaintext [DONE] before the encrypted [DONE]"
            );
            return Ok(());
        }
        let Ok(Value::Object(event)) = serde_json::from_str::<Value>(data) else {
            return Ok(());
        };
        if let Some(init) = event.get("e2e_init") {
            ensure!(self.stream_key.is_none(), "upstream sent a second e2e_init");
            let init = init.as_str().context("e2e_init is not a string")?;
            self.stream_key = Some(self.response_key.stream_key(init)?);
        } else if let Some(chunk) = event.get("e2e") {
            let key = self
                .stream_key
                .as_ref()
                .context("e2e chunk before e2e_init")?;
            ensure!(!self.done, "encrypted chunk after the encrypted [DONE]");
            let text = key.decrypt_chunk(chunk.as_str().context("e2e chunk is not a string")?)?;
            for inner in text.lines() {
                self.release(inner.trim_end(), output)?;
            }
        } else if let Some(error) = event.get("e2e_error") {
            bail!("upstream reported e2e_error: {error}");
        }
        Ok(())
    }

    fn release(&mut self, line: &str, output: &mut Vec<u8>) -> Result<()> {
        let Some(data) = line.strip_prefix("data:").map(str::trim_start) else {
            return Ok(());
        };
        if data == "[DONE]" {
            let usage = self
                .held_usage
                .take()
                .context("encrypted [DONE] without a preceding content-free usage frame")?;
            emit(output, &usage);
            emit(output, "[DONE]");
            self.done = true;
            return Ok(());
        }
        let mut chunk: Value = serde_json::from_str(data).context("decrypted chunk is not JSON")?;
        let usage = chunk.get("usage").filter(|usage| !usage.is_null());
        let content_free = chunk
            .get("choices")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty);
        if let (Some(usage), true) = (usage, content_free) {
            require_billable(usage)?;
            self.check_chunk(&chunk)?;
            self.held_usage = Some(data.to_owned());
            return Ok(());
        }
        self.check_chunk(&chunk)?;
        self.held_usage = None;
        if let Some(fields) = chunk.as_object_mut() {
            fields.remove("usage");
        }
        emit(output, &chunk.to_string());
        Ok(())
    }

    fn check_chunk(&mut self, chunk: &Value) -> Result<()> {
        if let Some(model) = chunk.get("model") {
            ensure!(
                model.as_str() == Some(self.model),
                "decrypted chunk names model {model}, expected {}",
                self.model
            );
        }
        if let Some(usage) = chunk.get("usage").filter(|usage| !usage.is_null()) {
            let total = usage_total(usage);
            ensure!(
                total >= self.usage_total,
                "cumulative usage fell from {} to {total}",
                self.usage_total
            );
            self.usage_total = total;
        }
        Ok(())
    }
}

fn emit(output: &mut Vec<u8>, data: &str) {
    output.extend_from_slice(b"data: ");
    output.extend_from_slice(data.as_bytes());
    output.extend_from_slice(b"\n\n");
}

/// The terminal usage frame is what the request is billed on: it must carry
/// non-negative integer prompt and completion counts, and a total, if given,
/// equal to their sum.
fn require_billable(usage: &Value) -> Result<()> {
    let count = |name: &str| {
        usage
            .get(name)
            .and_then(Value::as_u64)
            .with_context(|| format!("terminal usage has no integer {name}"))
    };
    let prompt = count("prompt_tokens")?;
    let completion = count("completion_tokens")?;
    if usage.get("total_tokens").is_some() {
        ensure!(
            Some(count("total_tokens")?) == prompt.checked_add(completion),
            "terminal usage total_tokens is not prompt_tokens + completion_tokens"
        );
    }
    Ok(())
}

fn usage_total(usage: &Value) -> u64 {
    let count = |name: &str| usage.get(name).and_then(Value::as_u64);
    count("total_tokens").unwrap_or_else(|| {
        count("prompt_tokens")
            .unwrap_or(0)
            .saturating_add(count("completion_tokens").unwrap_or(0))
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test fixtures fail the test")]
pub(crate) mod tests {
    use super::*;
    use crate::chutes_verify::crypto::encrypt_request;
    use crate::chutes_verify::crypto::tests::{Instance, Responder};

    const MODEL: &str = "zai-org/GLM-5.2-TEE";

    pub(crate) fn content(text: &str, total: u64) -> String {
        serde_json::json!({
            "model": MODEL,
            "choices": [{"index": 0, "delta": {"content": text}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": total - 10, "total_tokens": total},
        })
        .to_string()
    }

    pub(crate) fn usage_frame(total: u64) -> String {
        serde_json::json!({
            "model": MODEL,
            "choices": [],
            "usage": {"prompt_tokens": 10, "completion_tokens": total - 10, "total_tokens": total},
        })
        .to_string()
    }

    /// An upstream stream builder speaking the instance side of the protocol.
    pub(crate) struct Upstream {
        responder: Responder,
        pub(crate) decryptor: Option<StreamDecryptor>,
    }

    impl Upstream {
        pub(crate) fn new() -> Self {
            let instance = Instance::new();
            let payload = serde_json::json!({"model": MODEL})
                .as_object()
                .unwrap()
                .clone();
            let request = encrypt_request(&instance.public_b64, payload).unwrap();
            let responder = Responder::new(&instance.open_request(&request.blob));
            Self {
                responder,
                decryptor: Some(StreamDecryptor::new(request.response_key, MODEL)),
            }
        }

        pub(crate) fn init(&self) -> String {
            format!(
                "data: {}\n\n",
                serde_json::json!({"e2e_init": self.responder.stream_init()})
            )
        }

        pub(crate) fn encrypted(&self, data: &str) -> String {
            let chunk = self.responder.stream_chunk(&format!("data: {data}\n\n"));
            format!("data: {}\n\n", serde_json::json!({"e2e": chunk}))
        }

        /// A complete, well-formed upstream stream.
        pub(crate) fn happy(&self) -> Vec<String> {
            vec![
                self.init(),
                self.encrypted(&content("Hel", 11)),
                format!(
                    "data: {}\n\n",
                    serde_json::json!({"usage": {"total_tokens": 424_242}})
                ),
                self.encrypted(&content("lo", 12)),
                self.encrypted(&usage_frame(12)),
                self.encrypted("[DONE]"),
                "data: [DONE]\n\n".to_owned(),
            ]
        }

        fn run(&mut self, events: &[String]) -> Result<String> {
            let mut decryptor = self.decryptor.take().unwrap();
            let mut output = Vec::new();
            for event in events {
                output.extend(decryptor.feed(event.as_bytes())?);
            }
            decryptor.finish()?;
            Ok(String::from_utf8(output).unwrap())
        }
    }

    fn released_contents(output: &str) -> Vec<String> {
        output
            .split("\n\n")
            .filter_map(|event| event.strip_prefix("data: "))
            .filter(|data| *data != "[DONE]")
            .filter_map(|data| {
                let chunk: Value = serde_json::from_str(data).unwrap();
                chunk
                    .pointer("/choices/0/delta/content")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect()
    }

    #[test]
    fn well_formed_stream_releases_only_decrypted_content_then_done() {
        let mut upstream = Upstream::new();
        let events = upstream.happy();
        let output = upstream.run(&events).unwrap();
        assert_eq!(released_contents(&output), ["Hel", "lo"]);
        let tail = format!("data: {}\n\ndata: [DONE]\n\n", usage_frame(12));
        assert!(output.ends_with(&tail), "{output}");
        assert_eq!(output.matches("[DONE]").count(), 1);
        assert_eq!(
            output.matches("usage").count(),
            1,
            "running usage was forwarded"
        );
        assert!(!output.contains("424242"), "relay plaintext usage leaked");
    }

    #[test]
    fn events_split_across_reads_are_reassembled() {
        let mut upstream = Upstream::new();
        let joined = upstream.happy().concat();
        let mut decryptor = upstream.decryptor.take().unwrap();
        let mut output = Vec::new();
        for piece in joined.as_bytes().chunks(7) {
            output.extend(decryptor.feed(piece).unwrap());
        }
        decryptor.finish().unwrap();
        assert_eq!(
            released_contents(&String::from_utf8(output).unwrap()),
            ["Hel", "lo"]
        );
    }

    #[test]
    fn a_tampered_chunk_aborts() {
        let mut upstream = Upstream::new();
        let mut events = upstream.happy();
        let tampered = events[1].replacen("\"e2e\":\"", "\"e2e\":\"AAAA", 1);
        events[1] = tampered;
        let error = upstream.run(&events).unwrap_err();
        assert!(format!("{error:#}").contains("authentication"), "{error:#}");
    }

    #[test]
    fn a_missing_encrypted_done_aborts() {
        let mut upstream = Upstream::new();
        let mut events = upstream.happy();
        events.remove(5);
        let error = upstream.run(&events).unwrap_err();
        assert!(error.to_string().contains("[DONE]"), "{error:#}");
    }

    #[test]
    fn a_plaintext_done_first_aborts() {
        let mut upstream = Upstream::new();
        let mut events = upstream.happy();
        events.insert(2, "data: [DONE]\n\n".to_owned());
        let error = upstream.run(&events).unwrap_err();
        assert!(error.to_string().contains("plaintext [DONE]"), "{error:#}");
    }

    #[test]
    fn a_missing_terminal_usage_frame_aborts() {
        let mut upstream = Upstream::new();
        let mut events = upstream.happy();
        events.remove(4);
        let error = upstream.run(&events).unwrap_err();
        assert!(error.to_string().contains("usage frame"), "{error:#}");
    }

    #[test]
    fn a_usage_regression_aborts() {
        let mut upstream = Upstream::new();
        let mut events = upstream.happy();
        events[4] = upstream.encrypted(&usage_frame(11));
        events[3] = upstream.encrypted(&content("lo", 13));
        let error = upstream.run(&events).unwrap_err();
        assert!(error.to_string().contains("usage fell"), "{error:#}");
    }

    #[test]
    fn e2e_error_and_chunks_before_init_abort() {
        let mut upstream = Upstream::new();
        let mut errored = upstream.happy();
        errored.insert(2, "data: {\"e2e_error\":\"boom\"}\n\n".to_owned());
        assert!(upstream.run(&errored).is_err());

        let mut upstream = Upstream::new();
        let mut early = upstream.happy();
        early.remove(0);
        let error = upstream.run(&early).unwrap_err();
        assert!(error.to_string().contains("before e2e_init"), "{error:#}");
    }

    #[test]
    fn a_chunk_naming_another_model_aborts() {
        let mut upstream = Upstream::new();
        let mut events = upstream.happy();
        events[1] = upstream.encrypted(&content("x", 11).replace(MODEL, "other/model"));
        assert!(upstream.run(&events).is_err());
    }

    #[test]
    fn authenticated_chunks_are_released_in_arrival_order() {
        let bare = |text: &str| {
            serde_json::json!({"model": MODEL, "choices": [{"index": 0, "delta": {"content": text}}]})
                .to_string()
        };
        let mut upstream = Upstream::new();
        let mut events = upstream.happy();
        events[1] = upstream.encrypted(&bare("Hel"));
        events[3] = upstream.encrypted(&bare("lo"));
        events.swap(1, 3);
        let repeated = events[1].clone();
        events.insert(2, repeated);
        assert_eq!(
            released_contents(&upstream.run(&events).unwrap()),
            ["lo", "lo", "Hel"]
        );
    }

    #[test]
    fn usage_is_held_until_the_encrypted_done_validates() {
        let mut upstream = Upstream::new();
        let events = upstream.happy();
        let mut decryptor = upstream.decryptor.take().unwrap();
        let mut before_done = Vec::new();
        for event in &events[..5] {
            before_done.extend(decryptor.feed(event.as_bytes()).unwrap());
        }
        let before_done = String::from_utf8(before_done).unwrap();
        assert_eq!(released_contents(&before_done), ["Hel", "lo"]);
        assert!(!before_done.contains("usage"), "{before_done}");
        let after = String::from_utf8(decryptor.feed(events[5].as_bytes()).unwrap()).unwrap();
        assert!(
            after.starts_with(&format!("data: {}", usage_frame(12))),
            "{after}"
        );
    }

    #[test]
    fn a_terminal_frame_without_billable_counts_aborts() {
        for usage in [
            serde_json::json!({}),
            serde_json::json!({"prompt_tokens": 10}),
            serde_json::json!({"prompt_tokens": 10, "completion_tokens": 2.5}),
            serde_json::json!({"prompt_tokens": -1, "completion_tokens": 2}),
            serde_json::json!({"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 99}),
        ] {
            let mut upstream = Upstream::new();
            let mut events = upstream.happy();
            let frame = serde_json::json!({"model": MODEL, "choices": [], "usage": usage});
            events[4] = upstream.encrypted(&frame.to_string());
            let error = upstream.run(&events).unwrap_err();
            assert!(
                error.to_string().contains("terminal usage"),
                "{usage}: {error:#}"
            );
        }
    }
}
