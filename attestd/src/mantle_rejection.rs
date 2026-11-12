//! Bounded classification of a Bedrock Mantle `400` response.
//!
//! Mantle's error text is never relayed. A rejection is reduced to one of a
//! few known shapes, and only tokens that pass a strict character set and
//! length check are kept: a request field path, an `anthropic-beta` value that
//! the adapter itself forwarded, or a tool type tag. The public message is
//! then rebuilt by the adapter from those tokens. Anything else falls back to
//! the generic message.

use serde_json::Value;

use crate::gateway_contract::signals_drain;

const PROMPT_TOO_LONG: &str = "prompt is too long";
const BETA_PREFIX: &str = "Unexpected value(s) ";
const BETA_SUFFIX: &str = " for the `anthropic-beta` header";
const EXTRA_INPUT: &str = "Extra inputs are not permitted";
const FIELD_REQUIRED: &str = "Field required";
const TAG_PREFIX: &str = "Input tag '";
const TAG_SUFFIX: &str = "' found using 'type' does not match any of the expected tags";

const MAX_MESSAGE_BYTES: usize = 4096;
const MAX_TOKEN_BYTES: usize = 64;
const MAX_PATH_SEGMENTS: usize = 16;
const MAX_INDEX_DIGITS: usize = 6;
const MAX_BETA_VALUES: usize = 16;

/// Mantle error types the adapter repeats; any other value reads as
/// `invalid_request_error`.
const ERROR_TYPES: &[&str] = &[
    "invalid_request_error",
    "not_found_error",
    "permission_error",
    "request_too_large",
];
const DEFAULT_ERROR_TYPE: &str = "invalid_request_error";

const GENERIC_MESSAGE: &str = "Bedrock Mantle rejected the request as invalid";
const PROMPT_TOO_LONG_MESSAGE: &str = "Bedrock Mantle rejected the request: prompt is too long";

/// What a Mantle `400` said, reduced to safe tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MantleRejection {
    PromptTooLong,
    BetaValues(Vec<String>),
    UnnamedBeta,
    Field {
        path: FieldPath,
        problem: FieldProblem,
    },
    Unclassified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FieldProblem {
    ExtraInput,
    Required,
    UnknownTag(String),
    Other,
}

/// A validated request field path such as `tools.3.defer_loading`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldPath(Vec<String>);

impl FieldPath {
    fn parse(text: &str) -> Option<Self> {
        let segments: Vec<&str> = text.split('.').collect();
        if segments.len() > MAX_PATH_SEGMENTS || !segments.iter().all(|s| is_path_segment(s)) {
            return None;
        }
        Some(Self(segments.into_iter().map(str::to_owned).collect()))
    }

    fn dotted(&self) -> String {
        self.0.join(".")
    }

    /// JSON Pointer form, which survives the gm gateway's host redaction.
    fn pointer(&self) -> String {
        let mut pointer = String::new();
        for segment in &self.0 {
            pointer.push('/');
            pointer.push_str(segment);
        }
        pointer
    }
}

/// The adapter-written error for a Mantle `400`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublicRejection {
    pub(crate) error_type: &'static str,
    pub(crate) message: String,
    pub(crate) code: Option<&'static str>,
    pub(crate) param: Option<String>,
}

impl MantleRejection {
    /// Classify a Mantle `400` body. `forwarded_beta` is the `anthropic-beta`
    /// header the adapter sent; a named beta value is kept only when it is
    /// one of those values.
    pub(crate) fn classify(body: &[u8], forwarded_beta: Option<&str>) -> Self {
        if contains_ignore_ascii_case(body, PROMPT_TOO_LONG.as_bytes()) {
            return Self::PromptTooLong;
        }
        let Some(message) = error_message(body) else {
            return Self::Unclassified;
        };
        if message.len() > MAX_MESSAGE_BYTES {
            return Self::Unclassified;
        }
        let message = message.trim();
        if let Some(rest) = message.strip_prefix(BETA_PREFIX) {
            return classify_beta(rest, forwarded_beta);
        }
        if message
            .trim_end_matches('.')
            .eq_ignore_ascii_case("invalid beta flag")
        {
            return Self::UnnamedBeta;
        }
        classify_field(message)
    }

    /// The public error for this rejection. `upstream_type` is Mantle's
    /// `error.type`, repeated only when it is a known Anthropic error type.
    pub(crate) fn public(&self, upstream_type: Option<&str>) -> PublicRejection {
        let classified = self.classified(upstream_type);
        let generic = || PublicRejection {
            error_type: DEFAULT_ERROR_TYPE,
            message: GENERIC_MESSAGE.to_owned(),
            code: None,
            param: None,
        };
        match classified {
            Some(public) if !public_signals_drain(&public) => public,
            Some(_) | None => generic(),
        }
    }

    fn classified(&self, upstream_type: Option<&str>) -> Option<PublicRejection> {
        let error_type = upstream_type
            .and_then(|value| ERROR_TYPES.iter().find(|known| **known == value))
            .copied()
            .unwrap_or(DEFAULT_ERROR_TYPE);
        let public = |message: String, code: &'static str, param: Option<String>| PublicRejection {
            error_type,
            message,
            code: Some(code),
            param,
        };
        Some(match self {
            Self::Unclassified => return None,
            Self::PromptTooLong => PublicRejection {
                error_type: DEFAULT_ERROR_TYPE,
                message: PROMPT_TOO_LONG_MESSAGE.to_owned(),
                code: None,
                param: None,
            },
            Self::BetaValues(values) => {
                let quoted: Vec<String> = values.iter().map(|value| format!("`{value}`")).collect();
                public(
                    format!("{BETA_PREFIX}{}{BETA_SUFFIX}.", quoted.join(", ")),
                    "mantle_beta_rejected",
                    Some(values.join(",")),
                )
            }
            Self::UnnamedBeta => {
                public("invalid beta flag".to_owned(), "mantle_beta_rejected", None)
            }
            Self::Field { path, problem } => {
                let (detail, code) = match problem {
                    FieldProblem::ExtraInput => (EXTRA_INPUT.to_owned(), "mantle_extra_input"),
                    FieldProblem::Required => (FIELD_REQUIRED.to_owned(), "mantle_field_required"),
                    FieldProblem::UnknownTag(tag) => (
                        format!("{TAG_PREFIX}{tag}{TAG_SUFFIX}"),
                        "mantle_unknown_tag",
                    ),
                    FieldProblem::Other => (
                        "Bedrock Mantle rejected this field".to_owned(),
                        "mantle_field_rejected",
                    ),
                };
                public(
                    format!("{}: {detail}", path.dotted()),
                    code,
                    Some(path.pointer()),
                )
            }
        })
    }
}

fn public_signals_drain(public: &PublicRejection) -> bool {
    signals_drain(&public.message) || public.param.as_deref().is_some_and(signals_drain)
}

fn error_message(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let message = match value.get("error") {
        Some(Value::Object(error)) => error.get("message"),
        _ => value.get("message"),
    };
    message.and_then(Value::as_str).map(str::to_owned)
}

/// Mantle's `error.type`, when the body carries one.
pub(crate) fn error_type(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    value.get("error")?.get("type")?.as_str().map(str::to_owned)
}

fn classify_beta(rest: &str, forwarded_beta: Option<&str>) -> MantleRejection {
    let Some(list) = rest.find(BETA_SUFFIX).map(|end| &rest[..end]) else {
        return MantleRejection::Unclassified;
    };
    let forwarded: Vec<&str> = forwarded_beta
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .collect();
    let mut values = Vec::new();
    for item in list.split(',') {
        let Some(value) = item
            .trim()
            .strip_prefix('`')
            .and_then(|item| item.strip_suffix('`'))
        else {
            return MantleRejection::Unclassified;
        };
        if !is_beta_value(value) || !forwarded.contains(&value) || values.len() == MAX_BETA_VALUES {
            return MantleRejection::Unclassified;
        }
        values.push(value.to_owned());
    }
    MantleRejection::BetaValues(values)
}

fn classify_field(message: &str) -> MantleRejection {
    let Some((path, detail)) = message.split_once(": ") else {
        return MantleRejection::Unclassified;
    };
    let Some(path) = FieldPath::parse(path) else {
        return MantleRejection::Unclassified;
    };
    let detail = detail.trim();
    let problem = if detail.trim_end_matches('.') == EXTRA_INPUT {
        FieldProblem::ExtraInput
    } else if detail.trim_end_matches('.') == FIELD_REQUIRED {
        FieldProblem::Required
    } else if let Some(tag) = unknown_tag(detail) {
        FieldProblem::UnknownTag(tag)
    } else {
        FieldProblem::Other
    };
    MantleRejection::Field { path, problem }
}

fn unknown_tag(detail: &str) -> Option<String> {
    let rest = detail.strip_prefix(TAG_PREFIX)?;
    let end = rest.find(TAG_SUFFIX)?;
    let tag = &rest[..end];
    is_tag(tag).then(|| tag.to_owned())
}

fn is_path_segment(segment: &str) -> bool {
    let is_index = (1..=MAX_INDEX_DIGITS).contains(&segment.len())
        && segment.bytes().all(|byte| byte.is_ascii_digit());
    let is_name = (1..=MAX_TOKEN_BYTES).contains(&segment.len())
        && segment
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte == b'_')
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    is_index || is_name
}

fn is_beta_value(value: &str) -> bool {
    (1..=MAX_TOKEN_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn is_tag(tag: &str) -> bool {
    (1..=MAX_TOKEN_BYTES).contains(&tag.len())
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions use known-valid fixtures"
)]
mod tests {
    use super::*;
    use serde_json::json;

    const FORWARDED: &str =
        "claude-code-20250219, interleaved-thinking-2025-05-14,effort-2025-11-24";

    fn anthropic(message: &str) -> Vec<u8> {
        json!({"type": "error", "error": {"type": "invalid_request_error", "message": message}})
            .to_string()
            .into_bytes()
    }

    fn public_for(message: &str) -> PublicRejection {
        let body = anthropic(message);
        MantleRejection::classify(&body, Some(FORWARDED)).public(error_type(&body).as_deref())
    }

    fn generic() -> PublicRejection {
        MantleRejection::Unclassified.public(None)
    }

    fn path(text: &str) -> FieldPath {
        FieldPath::parse(text).expect("valid path")
    }

    #[test]
    fn named_beta_values_are_kept_only_when_the_adapter_forwarded_them() {
        let message = "Unexpected value(s) `effort-2025-11-24`, `interleaved-thinking-2025-05-14` \
                       for the `anthropic-beta` header. Please consult our documentation.";
        assert_eq!(
            public_for(message),
            PublicRejection {
                error_type: "invalid_request_error",
                message: "Unexpected value(s) `effort-2025-11-24`, \
                          `interleaved-thinking-2025-05-14` for the `anthropic-beta` header."
                    .to_owned(),
                code: Some("mantle_beta_rejected"),
                param: Some("effort-2025-11-24,interleaved-thinking-2025-05-14".to_owned()),
            }
        );
        for message in [
            "Unexpected value(s) `not-forwarded-2026-01-01` for the `anthropic-beta` header.",
            "Unexpected value(s) `effort-2025-11-24`, `not-forwarded` for the `anthropic-beta` header.",
            "Unexpected value(s) `effort 2025` for the `anthropic-beta` header.",
            "Unexpected value(s) effort-2025-11-24 for the `anthropic-beta` header.",
            "Unexpected value(s) `effort-2025-11-24` in the request.",
            "Unexpected value(s) `` for the `anthropic-beta` header.",
        ] {
            assert_eq!(public_for(message), generic(), "{message}");
        }
        let body =
            anthropic("Unexpected value(s) `effort-2025-11-24` for the `anthropic-beta` header.");
        assert_eq!(
            MantleRejection::classify(&body, None),
            MantleRejection::Unclassified
        );
    }

    #[test]
    fn beta_lists_are_bounded() {
        let names: Vec<String> = (0..=MAX_BETA_VALUES).map(|n| format!("flag-{n}")).collect();
        let forwarded = names.join(",");
        let quoted: Vec<String> = names.iter().map(|name| format!("`{name}`")).collect();
        let at_cap = anthropic(&format!(
            "{BETA_PREFIX}{}{BETA_SUFFIX}.",
            quoted[..MAX_BETA_VALUES].join(", ")
        ));
        assert_eq!(
            MantleRejection::classify(&at_cap, Some(&forwarded)),
            MantleRejection::BetaValues(names[..MAX_BETA_VALUES].to_vec())
        );
        let over_cap = anthropic(&format!("{BETA_PREFIX}{}{BETA_SUFFIX}.", quoted.join(", ")));
        assert_eq!(
            MantleRejection::classify(&over_cap, Some(&forwarded)),
            MantleRejection::Unclassified
        );
        let long = "a".repeat(MAX_TOKEN_BYTES + 1);
        let body = anthropic(&format!("{BETA_PREFIX}`{long}`{BETA_SUFFIX}."));
        assert_eq!(
            MantleRejection::classify(&body, Some(&long)),
            MantleRejection::Unclassified
        );
        let longest = "a".repeat(MAX_TOKEN_BYTES);
        let body = anthropic(&format!("{BETA_PREFIX}`{longest}`{BETA_SUFFIX}."));
        assert_eq!(
            MantleRejection::classify(&body, Some(&longest)),
            MantleRejection::BetaValues(vec![longest])
        );
    }

    #[test]
    fn a_bare_invalid_beta_flag_is_classified_without_a_name() {
        for message in [
            "invalid beta flag",
            "Invalid beta flag.",
            "  invalid beta flag  ",
        ] {
            assert_eq!(
                public_for(message),
                PublicRejection {
                    error_type: "invalid_request_error",
                    message: "invalid beta flag".to_owned(),
                    code: Some("mantle_beta_rejected"),
                    param: None,
                },
                "{message}"
            );
        }
        assert_eq!(public_for("invalid beta flag: claude-code"), generic());
    }

    #[test]
    fn field_rejections_keep_only_the_path_and_known_reason() {
        let cases = [
            (
                "context_management: Extra inputs are not permitted",
                "context_management: Extra inputs are not permitted",
                "mantle_extra_input",
                "/context_management",
            ),
            (
                "tools.3.custom.defer_loading: Extra inputs are not permitted.",
                "tools.3.custom.defer_loading: Extra inputs are not permitted",
                "mantle_extra_input",
                "/tools/3/custom/defer_loading",
            ),
            (
                "messages.0.content: Field required",
                "messages.0.content: Field required",
                "mantle_field_required",
                "/messages/0/content",
            ),
            (
                "tools.5: Input tag 'advisor_20260301' found using 'type' does not match any \
                 of the expected tags: 'bash_20250124', 'custom'",
                "tools.5: Input tag 'advisor_20260301' found using 'type' does not match any \
                 of the expected tags",
                "mantle_unknown_tag",
                "/tools/5",
            ),
            (
                "thinking.type: Input should be 'enabled' or 'disabled'",
                "thinking.type: Bedrock Mantle rejected this field",
                "mantle_field_rejected",
                "/thinking/type",
            ),
        ];
        for (upstream, message, code, param) in cases {
            assert_eq!(
                public_for(upstream),
                PublicRejection {
                    error_type: "invalid_request_error",
                    message: message.to_owned(),
                    code: Some(code),
                    param: Some(param.to_owned()),
                },
                "{upstream}"
            );
        }
    }

    #[test]
    fn content_echoed_by_mantle_is_never_relayed() {
        let sentinel = "PRIVATE_PROMPT_7f3a";
        for message in [
            format!("messages.0.content.0.text: Input should be a valid string, got '{sentinel}'"),
            format!("tools.0: Input tag '{sentinel} x' found using 'type' does not match any of the expected tags"),
            format!("{sentinel} is not allowed: Extra inputs are not permitted"),
            format!("Unexpected value(s) `{sentinel}` for the `anthropic-beta` header."),
            format!("The request contained: {sentinel}"),
        ] {
            let public = public_for(&message);
            let rendered = format!("{public:?}");
            assert!(!rendered.contains(sentinel), "{message} -> {rendered}");
        }
    }

    #[test]
    fn malformed_paths_fall_back_to_the_generic_message() {
        let deep = vec!["a"; MAX_PATH_SEGMENTS + 1].join(".");
        let deepest = vec!["a"; MAX_PATH_SEGMENTS].join(".");
        let long_name = "a".repeat(MAX_TOKEN_BYTES + 1);
        let long_index = "1".repeat(MAX_INDEX_DIGITS + 1);
        for path in [
            String::new(),
            "tools..3".to_owned(),
            ".tools".to_owned(),
            "Tools.3".to_owned(),
            "tools.3a".to_owned(),
            "tools-3".to_owned(),
            "tools.3 extra".to_owned(),
            "messages.0.content[0]".to_owned(),
            "ValidationException".to_owned(),
            deep,
            long_name,
            format!("tools.{long_index}"),
        ] {
            assert_eq!(
                public_for(&format!("{path}: Extra inputs are not permitted")),
                generic(),
                "{path}"
            );
        }
        assert_eq!(
            FieldPath::parse(&deepest).map(|path| path.dotted()),
            Some(deepest)
        );
        let longest = "a".repeat(MAX_TOKEN_BYTES);
        assert!(FieldPath::parse(&longest).is_some());
        assert!(FieldPath::parse(&"1".repeat(MAX_INDEX_DIGITS)).is_some());
        assert!(FieldPath::parse("_private.x9").is_some());
    }

    #[test]
    fn tags_are_bounded_to_a_safe_alphabet() {
        let tag_message = |tag: &str| format!("tools.0: {TAG_PREFIX}{tag}{TAG_SUFFIX}: 'custom'");
        let longest = "a".repeat(MAX_TOKEN_BYTES);
        assert_eq!(
            MantleRejection::classify(&anthropic(&tag_message(&longest)), None),
            MantleRejection::Field {
                path: path("tools.0"),
                problem: FieldProblem::UnknownTag(longest),
            }
        );
        for tag in [
            String::new(),
            "a".repeat(MAX_TOKEN_BYTES + 1),
            "has space".to_owned(),
            "dash-ed".to_owned(),
        ] {
            assert_eq!(
                MantleRejection::classify(&anthropic(&tag_message(&tag)), None),
                MantleRejection::Field {
                    path: path("tools.0"),
                    problem: FieldProblem::Other,
                },
                "{tag}"
            );
        }
    }

    #[test]
    fn prompt_too_long_keeps_its_fixed_message() {
        for body in [
            anthropic("prompt is too long: 250000 tokens > 200000 maximum"),
            br#"{"message":"Prompt Is Too Long"}"#.to_vec(),
            b"not json, but prompt is too long".to_vec(),
        ] {
            assert_eq!(
                MantleRejection::classify(&body, None).public(None),
                PublicRejection {
                    error_type: "invalid_request_error",
                    message: PROMPT_TOO_LONG_MESSAGE.to_owned(),
                    code: None,
                    param: None,
                }
            );
        }
    }

    #[test]
    fn odd_bodies_fall_back_to_the_generic_message() {
        let oversized = anthropic(&format!(
            "context_management: Extra inputs are not permitted{}",
            " ".repeat(MAX_MESSAGE_BYTES)
        ));
        let at_limit = anthropic(&format!(
            "context_management: Extra inputs are not permitted{}",
            " ".repeat(MAX_MESSAGE_BYTES - EXTRA_INPUT.len() - "context_management: ".len())
        ));
        assert_ne!(
            MantleRejection::classify(&at_limit, None),
            MantleRejection::Unclassified
        );
        for body in [
            Vec::new(),
            b"not json".to_vec(),
            b"[]".to_vec(),
            br#"{"error":"context_management: Extra inputs are not permitted"}"#.to_vec(),
            br#"{"error":{"type":"invalid_request_error"}}"#.to_vec(),
            br#"{"error":{"message":7}}"#.to_vec(),
            br#"{"error":{"message":"no separator here"}}"#.to_vec(),
            oversized,
            vec![0xff; 32],
        ] {
            assert_eq!(
                MantleRejection::classify(&body, Some(FORWARDED)).public(None),
                generic(),
                "{}",
                String::from_utf8_lossy(&body)
            );
        }
        assert_eq!(
            MantleRejection::classify(
                br#"{"message":"context_management: Extra inputs are not permitted"}"#,
                None
            ),
            MantleRejection::Field {
                path: path("context_management"),
                problem: FieldProblem::ExtraInput,
            }
        );
    }

    #[test]
    fn only_known_upstream_error_types_are_repeated() {
        let rejection = MantleRejection::Field {
            path: path("model"),
            problem: FieldProblem::Required,
        };
        for known in ERROR_TYPES {
            assert_eq!(rejection.public(Some(known)).error_type, *known);
        }
        for unknown in [None, Some("api_error"), Some("PRIVATE_PROMPT"), Some("")] {
            assert_eq!(
                rejection.public(unknown).error_type,
                DEFAULT_ERROR_TYPE,
                "{unknown:?}"
            );
        }
        assert_eq!(
            error_type(&anthropic("x")).as_deref(),
            Some("invalid_request_error")
        );
        assert_eq!(error_type(br#"{"message":"x"}"#), None);
    }

    #[test]
    fn a_classification_that_reads_as_an_account_drain_is_not_relayed() {
        for message in [
            "invalid_api_key: Extra inputs are not permitted",
            "tools.0.insufficient_quota: Field required",
        ] {
            assert_eq!(public_for(message), generic(), "{message}");
        }
        let drain_param = MantleRejection::BetaValues(vec!["x".to_owned()]);
        let public = drain_param.public(None);
        assert!(!public_signals_drain(&public));
        assert!(public_signals_drain(&PublicRejection {
            param: Some("invalid_api_key".to_owned()),
            ..public
        }));
    }
}
