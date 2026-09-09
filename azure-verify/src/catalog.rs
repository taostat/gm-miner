use crate::AzureProvider;

const AZURE_OPENAI_MODEL_IDS: &[&str] = &[
    "gpt-5.4",
    "gpt-5.4-mini",
    "gpt-5.4-nano",
    "gpt-5.5",
    "gpt-5.5-pro",
    "gpt-5.6",
    "gpt-5.6-luna",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
    "o3",
    "o4-mini",
];

const FOUNDRY_MODEL_IDS: &[&str] = &[
    "claude-fable-5",
    "claude-fable-5-1",
    "claude-haiku-4-5",
    "claude-opus-4-6",
    "claude-opus-4-7",
    "claude-opus-4-8",
    "claude-opus-5",
    "claude-sonnet-4-6",
    "claude-sonnet-5",
];

impl AzureProvider {
    pub(crate) fn catalog_ids(self) -> &'static [&'static str] {
        match self {
            Self::OpenAi => AZURE_OPENAI_MODEL_IDS,
            Self::Foundry => FOUNDRY_MODEL_IDS,
        }
    }

    pub(crate) fn model_format(self) -> &'static str {
        match self {
            Self::OpenAi => "OpenAI",
            Self::Foundry => "Anthropic",
        }
    }
}
