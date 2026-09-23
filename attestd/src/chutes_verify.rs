//! Attested end-to-end encrypted transport to Chutes `-TEE` models.
//!
//! Admission verifies, per `(credential, chute)`, that each discovered
//! instance's ML-KEM key is bound into a genuine `UpToDate` TDX quote whose
//! measurements Chutes publishes, alongside NRAS-verified GPUs under the same
//! nonce. Requests are then encrypted end to end to that key, and responses
//! are released only after they authenticate under it.

pub mod admission;
pub mod client;
pub mod crypto;
pub mod error;
pub mod evidence;
pub mod forward;
pub mod references;
pub mod stream;

pub use admission::Admissions;
pub use client::LiveChutes;
pub use error::ChutesError;
pub use forward::ChutesVerifier;

/// Header carrying the upstream model id Envoy selected for this request.
pub const SELECTOR_HEADER: &str = "x-gm-upstream-model";
pub const CHAT_COMPLETIONS: &str = "/v1/chat/completions";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChutesTarget {
    pub model: &'static str,
    pub chute_id: &'static str,
}

/// Every Chutes `-TEE` model gm sources, with the chute Chutes serves it from
/// (`llm.chutes.ai/v1/models`, 2026-09-23). `--verify-once` re-checks the pairs.
pub const TARGETS: [ChutesTarget; 13] = [
    target("Qwen/Qwen3-32B-TEE", "ac059e33-eb27-541c-b9a9-24b214036475"),
    target(
        "google/gemma-4-31B-turbo-TEE",
        "42ee92ba-a537-5a73-8741-876067750db7",
    ),
    target(
        "zai-org/GLM-5.1-TEE",
        "b048fe26-0352-5c46-acf7-335e527e7f3d",
    ),
    target(
        "deepseek-ai/DeepSeek-V3.2-TEE",
        "398651e1-5f85-5e50-a513-7c5324e8e839",
    ),
    target(
        "moonshotai/Kimi-K2.6-TEE",
        "aac09863-35b4-5d9b-9b67-6e6a9d54273a",
    ),
    target(
        "Qwen/Qwen3.5-397B-A17B-TEE",
        "51a4284a-a5a0-5e44-a9cc-6af5a2abfbcf",
    ),
    target(
        "Qwen/Qwen3.6-27B-TEE",
        "7aa5e899-c0ba-5482-af48-d3f31d635c9f",
    ),
    target(
        "Qwen/Qwen3-235B-A22B-Thinking-2507-TEE",
        "21d129e5-8426-5c29-a6be-844e0f5f5e30",
    ),
    target(
        "unsloth/Mistral-Nemo-Instruct-2407-TEE",
        "7725a31d-28df-5bb7-9d29-c23b49df5472",
    ),
    target(
        "zai-org/GLM-5.2-TEE",
        "08901219-159f-55a7-87cf-9d0d02744668",
    ),
    target(
        "deepseek-ai/DeepSeek-V4-Flash-0731-TEE",
        "b4d58772-e72b-55d1-9d73-d30dff6d2ed8",
    ),
    target(
        "moonshotai/Kimi-K3-TEE",
        "0bb5d4c2-b5da-587d-b88e-62b4839028ec",
    ),
    target(
        "Nemotron-3-Nano-Omni-30B-TEE",
        "761ccdab-2e3d-5268-ab03-55f8ba94a80c",
    ),
];

const fn target(model: &'static str, chute_id: &'static str) -> ChutesTarget {
    ChutesTarget { model, chute_id }
}

#[must_use]
pub fn target_for_model(model: &str) -> Option<ChutesTarget> {
    TARGETS.iter().copied().find(|target| target.model == model)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_target_is_a_distinct_tee_model_on_a_distinct_chute() {
        let mut models = TARGETS.map(|target| target.model).to_vec();
        let mut chutes = TARGETS.map(|target| target.chute_id).to_vec();
        models.sort_unstable();
        models.dedup();
        chutes.sort_unstable();
        chutes.dedup();
        assert_eq!(models.len(), TARGETS.len());
        assert_eq!(chutes.len(), TARGETS.len());
        assert!(TARGETS.iter().all(|target| target.model.ends_with("-TEE")));
    }

    #[test]
    fn selectors_off_the_list_have_no_target() {
        assert!(target_for_model("zai-org/GLM-5.2").is_none());
        assert!(target_for_model("zai-org/glm-5.2-tee").is_none());
        assert_eq!(
            target_for_model("zai-org/GLM-5.2-TEE").map(|target| target.chute_id),
            Some("08901219-159f-55a7-87cf-9d0d02744668")
        );
    }
}
