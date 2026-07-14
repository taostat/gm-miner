use reqwest::StatusCode;

use crate::arm::AzureHttpStatusError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerificationFailureKind {
    Transient,
    Definitive,
}

pub(crate) fn classify_verification_error(error: &anyhow::Error) -> VerificationFailureKind {
    for cause in error.chain() {
        if let Some(status_error) = cause.downcast_ref::<AzureHttpStatusError>() {
            return if status_is_transient(status_error.status) {
                VerificationFailureKind::Transient
            } else {
                VerificationFailureKind::Definitive
            };
        }
        if let Some(reqwest_error) = cause.downcast_ref::<reqwest::Error>() {
            if reqwest_error.is_timeout()
                || reqwest_error.is_connect()
                || reqwest_error.is_decode()
                || reqwest_error.status().is_some_and(status_is_transient)
            {
                return VerificationFailureKind::Transient;
            }
        }
    }
    VerificationFailureKind::Definitive
}

pub(crate) fn status_is_transient(status: StatusCode) -> bool {
    status.is_server_error()
        || matches!(
            status,
            StatusCode::TOO_MANY_REQUESTS | StatusCode::REQUEST_TIMEOUT
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arm::AzureHttpStatusError;

    #[test]
    fn verification_error_classification_separates_transient_from_definitive() {
        let transient = anyhow::Error::new(AzureHttpStatusError {
            label: "Azure Cognitive Services account",
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: "temporary outage".to_owned(),
        });
        assert_eq!(
            classify_verification_error(&transient),
            VerificationFailureKind::Transient
        );

        for status in [StatusCode::TOO_MANY_REQUESTS, StatusCode::REQUEST_TIMEOUT] {
            let transient_status = anyhow::Error::new(AzureHttpStatusError {
                label: "Azure Cognitive Services account",
                status,
                body: "throttled".to_owned(),
            });
            assert_eq!(
                classify_verification_error(&transient_status),
                VerificationFailureKind::Transient
            );
        }

        let definitive_status = anyhow::Error::new(AzureHttpStatusError {
            label: "Azure Cognitive Services account",
            status: StatusCode::FORBIDDEN,
            body: "access denied".to_owned(),
        });
        assert_eq!(
            classify_verification_error(&definitive_status),
            VerificationFailureKind::Definitive
        );

        let definitive_policy =
            anyhow::anyhow!("Azure account properties.raiMonitorConfig must be null or absent");
        assert_eq!(
            classify_verification_error(&definitive_policy),
            VerificationFailureKind::Definitive
        );
    }
}
