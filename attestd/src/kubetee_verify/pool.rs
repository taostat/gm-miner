use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Bytes;
use hyper::body::{Body as HttpBody, Frame, SizeHint};

pub use crate::attested_pool::{Attested, Lease, Pool, MAX_AGE, MAX_IDLE, MAX_REQUESTS};
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(60);
pub const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_age: Duration,
    pub max_requests: usize,
    pub max_idle: usize,
    pub fetch_timeout: Duration,
    pub request_read_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_age: MAX_AGE,
            max_requests: MAX_REQUESTS,
            max_idle: MAX_IDLE,
            fetch_timeout: FETCH_TIMEOUT,
            request_read_timeout: REQUEST_READ_TIMEOUT,
        }
    }
}

impl Limits {
    #[must_use]
    pub fn pool_limits(self) -> crate::attested_pool::PoolLimits {
        crate::attested_pool::PoolLimits {
            age: self.max_age,
            // Preserve KubeTEE's reuse policy when sharing NEAR's pool.
            idle_age: None,
            requests: self.max_requests,
            idle: self.max_idle,
        }
    }
}

// Only trailers change, so preserve the data length as well as end-of-stream.
// BodyExt::map_frame discards size hints because it also permits changing data.
pub(crate) struct SupplierBody<B>(pub B);

impl<B: HttpBody<Data = Bytes> + Unpin> HttpBody for SupplierBody<B> {
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Pin::new(&mut self.get_mut().0)
            .poll_frame(context)
            .map_ok(strip_supplier_trailers)
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.0.size_hint()
    }
}

fn strip_supplier_trailers(frame: Frame<Bytes>) -> Frame<Bytes> {
    match frame.into_trailers() {
        Ok(mut trailers) => {
            super::strip_supplier_headers(&mut trailers);
            Frame::trailers(trailers)
        }
        Err(frame) => frame,
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test values are known to be valid")]
mod tests {
    use super::*;
    use axum::body::Body;

    #[tokio::test]
    async fn supplier_filter_preserves_response_length_and_end_of_stream() {
        use http_body_util::BodyExt as _;
        use hyper::body::Body as _;

        let mut body = Body::new(SupplierBody(Body::from("completion")));
        assert_eq!(body.size_hint().exact(), Some(10));
        assert!(!body.is_end_stream());
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            "completion"
        );
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(body.is_end_stream());
    }

    #[test]
    fn supplier_trailers_are_removed_and_data_is_untouched() {
        let mut trailers = axum::http::HeaderMap::new();
        trailers.insert("x-kubetee-attestation-quote", "q".parse().unwrap());
        trailers.insert("x-litellm-key-spend", "0.14".parse().unwrap());
        trailers.insert("x-request-id", "m".parse().unwrap());
        let stripped = strip_supplier_trailers(Frame::trailers(trailers))
            .into_trailers()
            .unwrap();
        assert!(!stripped.contains_key("x-kubetee-attestation-quote"));
        assert!(!stripped.contains_key("x-litellm-key-spend"));
        assert!(stripped.contains_key("x-request-id"));
        let data = strip_supplier_trailers(Frame::data(Bytes::from_static(b"x-kubetee-")));
        assert_eq!(data.into_data().unwrap(), Bytes::from_static(b"x-kubetee-"));
    }
}
