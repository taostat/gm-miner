//! Chutes E2E wire crypto: ML-KEM-768, HKDF-SHA256 salted with the first 16
//! ciphertext bytes, ChaCha20-Poly1305 with no associated data, over gzip JSON.
//! Matches `chutes-e2ee-transport` 874061f `crypto.py`.

use std::io::{Read as _, Write as _};

use anyhow::{ensure, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use flate2::bufread::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use ml_kem::{
    Decapsulate as _, Encapsulate as _, Kem as _, KeyExport as _, MlKem768, TryKeyInit as _,
};
use rand::Rng as _;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN};
use ring::hkdf::{Salt, HKDF_SHA256};
use serde_json::{Map, Value};

pub const MLKEM768_PUBLIC_KEY_BYTES: usize = 1_184;
pub const MLKEM768_CIPHERTEXT_BYTES: usize = 1_088;
const TAG_BYTES: usize = 16;
const INFO_REQUEST: &[u8] = b"e2e-req-v1";
const INFO_RESPONSE: &[u8] = b"e2e-resp-v1";
const INFO_STREAM: &[u8] = b"e2e-stream-v1";
pub const MAX_PLAINTEXT_BYTES: usize = 32 * 1024 * 1024;

type DecapsulationKey = ml_kem::DecapsulationKey<MlKem768>;
type EncapsulationKey = ml_kem::EncapsulationKey<MlKem768>;

/// The per-request ML-KEM key the instance encrypts its response to.
pub struct ResponseKey(DecapsulationKey);

/// The symmetric key of one encrypted response stream.
pub struct StreamKey(LessSafeKey);

/// An encrypted request body and the key that opens its response.
pub struct EncryptedRequest {
    pub blob: Vec<u8>,
    pub response_key: ResponseKey,
}

/// Encrypt `payload` to an instance's ML-KEM key, adding a fresh
/// `e2e_response_pk` for the response.
///
/// # Errors
///
/// Returns an error when the instance key is malformed or the payload
/// already carries an `e2e_` field.
pub fn encrypt_request(
    instance_key_b64: &str,
    mut payload: Map<String, Value>,
) -> Result<EncryptedRequest> {
    ensure!(
        !payload.keys().any(|key| key.starts_with("e2e_")),
        "e2e_ fields are reserved for the transport"
    );
    let instance_key = decode_public_key(instance_key_b64)?;
    let (response_secret, response_public) = MlKem768::generate_keypair();
    payload.insert(
        "e2e_response_pk".to_owned(),
        Value::String(BASE64.encode(response_public.to_bytes())),
    );
    let plaintext = gzip(&serde_json::to_vec(&payload).context("encode request JSON")?)?;
    let (kem_ciphertext, shared) = instance_key.encapsulate();
    let key = derive_key(shared.as_slice(), kem_ciphertext.as_slice(), INFO_REQUEST)?;
    let mut blob = kem_ciphertext.to_vec();
    blob.extend_from_slice(&seal(&key, plaintext)?);
    Ok(EncryptedRequest {
        blob,
        response_key: ResponseKey(response_secret),
    })
}

impl ResponseKey {
    /// Decrypt a non-streaming response blob to its JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the blob is truncated, fails authentication, or
    /// is not a single gzip member.
    pub fn decrypt_response(&self, blob: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            blob.len() >= MLKEM768_CIPHERTEXT_BYTES + NONCE_LEN + TAG_BYTES,
            "encrypted response is truncated"
        );
        let (kem_ciphertext, sealed) = blob.split_at(MLKEM768_CIPHERTEXT_BYTES);
        let key = self.derive(kem_ciphertext, INFO_RESPONSE)?;
        gunzip(&open(&key, sealed).context("authenticate encrypted response")?)
    }

    /// Derive the stream key from an `e2e_init` event's ML-KEM ciphertext.
    ///
    /// # Errors
    ///
    /// Returns an error when the ciphertext is not base64 ML-KEM-768.
    pub fn stream_key(&self, init_b64: &str) -> Result<StreamKey> {
        let kem_ciphertext = BASE64.decode(init_b64).context("decode e2e_init")?;
        Ok(StreamKey(self.derive(&kem_ciphertext, INFO_STREAM)?))
    }

    fn derive(&self, kem_ciphertext: &[u8], info: &[u8]) -> Result<LessSafeKey> {
        let shared = self.0.decapsulate_slice(kem_ciphertext).map_err(|_| {
            anyhow::anyhow!("ML-KEM ciphertext is not {MLKEM768_CIPHERTEXT_BYTES} bytes")
        })?;
        derive_key(shared.as_slice(), kem_ciphertext, info)
    }
}

impl StreamKey {
    /// Decrypt one `e2e` stream chunk to its UTF-8 text.
    ///
    /// # Errors
    ///
    /// Returns an error when the chunk fails authentication or is not UTF-8.
    pub fn decrypt_chunk(&self, chunk_b64: &str) -> Result<String> {
        let sealed = BASE64.decode(chunk_b64).context("decode e2e chunk")?;
        String::from_utf8(open(&self.0, &sealed).context("authenticate e2e chunk")?)
            .context("e2e chunk is not UTF-8")
    }
}

fn decode_public_key(value: &str) -> Result<EncapsulationKey> {
    let bytes = BASE64.decode(value).context("decode instance ML-KEM key")?;
    ensure!(
        bytes.len() == MLKEM768_PUBLIC_KEY_BYTES,
        "instance ML-KEM key is {} bytes, expected {MLKEM768_PUBLIC_KEY_BYTES}",
        bytes.len()
    );
    EncapsulationKey::new_from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("instance ML-KEM key is invalid"))
}

/// Check an instance key is a canonical base64 ML-KEM-768 encapsulation key.
///
/// # Errors
///
/// Returns an error when it is not.
pub fn validate_public_key(value: &str) -> Result<()> {
    decode_public_key(value)?;
    ensure!(
        BASE64.encode(BASE64.decode(value)?) == value,
        "instance ML-KEM key is not canonical base64"
    );
    Ok(())
}

fn derive_key(shared: &[u8], kem_ciphertext: &[u8], info: &[u8]) -> Result<LessSafeKey> {
    ensure!(
        kem_ciphertext.len() >= 16,
        "ML-KEM ciphertext is too short to salt the KDF"
    );
    let info = [info];
    let prk = Salt::new(HKDF_SHA256, &kem_ciphertext[..16]).extract(shared);
    let okm = prk
        .expand(&info, &CHACHA20_POLY1305)
        .map_err(|_| anyhow::anyhow!("derive E2E key"))?;
    Ok(LessSafeKey::new(UnboundKey::from(okm)))
}

fn seal(key: &LessSafeKey, mut plaintext: Vec<u8>) -> Result<Vec<u8>> {
    let mut nonce = [0_u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::empty(),
        &mut plaintext,
    )
    .map_err(|_| anyhow::anyhow!("encrypt E2E payload"))?;
    let mut sealed = nonce.to_vec();
    sealed.append(&mut plaintext);
    Ok(sealed)
}

fn open(key: &LessSafeKey, sealed: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        sealed.len() >= NONCE_LEN + TAG_BYTES,
        "E2E ciphertext is truncated"
    );
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce =
        Nonce::try_assume_unique_for_key(nonce).map_err(|_| anyhow::anyhow!("E2E nonce"))?;
    let mut buffer = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::empty(), &mut buffer)
        .map_err(|_| anyhow::anyhow!("E2E ciphertext failed authentication"))?;
    Ok(plaintext.to_vec())
}

fn gzip(input: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(input).context("gzip E2E payload")?;
    encoder.finish().context("gzip E2E payload")
}

// The decoder requires exactly one gzip member and rejects trailing bytes.
fn gunzip(input: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(input);
    let mut output = Vec::new();
    (&mut decoder)
        .take(MAX_PLAINTEXT_BYTES as u64 + 1)
        .read_to_end(&mut output)
        .context("gunzip E2E payload")?;
    ensure!(
        output.len() <= MAX_PLAINTEXT_BYTES,
        "E2E payload exceeds {MAX_PLAINTEXT_BYTES} bytes"
    );
    ensure!(
        decoder.into_inner().is_empty(),
        "E2E payload has bytes after its gzip member"
    );
    Ok(output)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test fixtures fail the test")]
pub(crate) mod tests {
    use super::*;

    /// The instance side of the protocol: the key discovery advertises.
    pub(crate) struct Instance {
        secret: DecapsulationKey,
        pub(crate) public_b64: String,
    }

    impl Instance {
        pub(crate) fn new() -> Self {
            let (secret, public) = MlKem768::generate_keypair();
            Self {
                secret,
                public_b64: BASE64.encode(public.to_bytes()),
            }
        }

        /// Open a request blob as the instance would, returning its JSON.
        pub(crate) fn open_request(&self, blob: &[u8]) -> Map<String, Value> {
            let (kem_ciphertext, sealed) = blob.split_at(MLKEM768_CIPHERTEXT_BYTES);
            let shared = self.secret.decapsulate_slice(kem_ciphertext).unwrap();
            let key = derive_key(shared.as_slice(), kem_ciphertext, INFO_REQUEST).unwrap();
            serde_json::from_slice(&gunzip(&open(&key, sealed).unwrap()).unwrap()).unwrap()
        }
    }

    /// The instance's encryptor for one response, keyed to `e2e_response_pk`.
    pub(crate) struct Responder {
        kem_ciphertext: Vec<u8>,
        shared: Vec<u8>,
    }

    impl Responder {
        pub(crate) fn new(request: &Map<String, Value>) -> Self {
            let public = BASE64
                .decode(request["e2e_response_pk"].as_str().unwrap())
                .unwrap();
            let (kem_ciphertext, shared) = EncapsulationKey::new_from_slice(&public)
                .unwrap()
                .encapsulate();
            Self {
                kem_ciphertext: kem_ciphertext.to_vec(),
                shared: shared.to_vec(),
            }
        }

        pub(crate) fn response_blob(&self, json: &[u8]) -> Vec<u8> {
            let key = derive_key(&self.shared, &self.kem_ciphertext, INFO_RESPONSE).unwrap();
            let mut blob = self.kem_ciphertext.clone();
            blob.extend_from_slice(&seal(&key, gzip(json).unwrap()).unwrap());
            blob
        }

        pub(crate) fn stream_init(&self) -> String {
            BASE64.encode(&self.kem_ciphertext)
        }

        pub(crate) fn stream_chunk(&self, text: &str) -> String {
            let key = derive_key(&self.shared, &self.kem_ciphertext, INFO_STREAM).unwrap();
            BASE64.encode(seal(&key, text.as_bytes().to_vec()).unwrap())
        }
    }

    fn payload() -> Map<String, Value> {
        serde_json::json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]})
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn request_and_response_round_trip_under_the_instance_key() {
        let instance = Instance::new();
        let request = encrypt_request(&instance.public_b64, payload()).unwrap();
        let opened = instance.open_request(&request.blob);
        assert_eq!(opened["messages"], payload()["messages"]);
        let response = Responder::new(&opened).response_blob(br#"{"ok":true}"#);
        assert_eq!(
            request.response_key.decrypt_response(&response).unwrap(),
            br#"{"ok":true}"#
        );
    }

    #[test]
    fn a_tampered_or_misdirected_response_fails_closed() {
        let instance = Instance::new();
        let request = encrypt_request(&instance.public_b64, payload()).unwrap();
        let mut response =
            Responder::new(&instance.open_request(&request.blob)).response_blob(b"{}");
        let other = encrypt_request(&instance.public_b64, payload()).unwrap();
        assert!(other.response_key.decrypt_response(&response).is_err());
        let last = response.len() - 1;
        response[last] ^= 1;
        assert!(request.response_key.decrypt_response(&response).is_err());
    }

    #[test]
    fn stream_chunks_open_only_under_their_stream_key() {
        let instance = Instance::new();
        let request = encrypt_request(&instance.public_b64, payload()).unwrap();
        let responder = Responder::new(&instance.open_request(&request.blob));
        let key = request
            .response_key
            .stream_key(&responder.stream_init())
            .unwrap();
        assert_eq!(
            key.decrypt_chunk(&responder.stream_chunk("data: x"))
                .unwrap(),
            "data: x"
        );
        let mut tampered = BASE64.decode(responder.stream_chunk("data: x")).unwrap();
        tampered[NONCE_LEN] ^= 1;
        assert!(key.decrypt_chunk(&BASE64.encode(tampered)).is_err());
    }

    #[test]
    fn reserved_fields_and_bad_keys_are_refused_before_encryption() {
        let instance = Instance::new();
        let mut reserved = payload();
        reserved.insert("e2e_response_pk".to_owned(), Value::from("attacker"));
        assert!(encrypt_request(&instance.public_b64, reserved).is_err());
        assert!(encrypt_request(&BASE64.encode([0_u8; 32]), payload()).is_err());
        assert!(validate_public_key(&instance.public_b64).is_ok());
        assert!(validate_public_key(&format!("{}=", instance.public_b64)).is_err());
    }

    #[test]
    fn bytes_after_the_gzip_member_are_rejected() {
        let mut compressed = gzip(br#"{"ok":true}"#).unwrap();
        assert_eq!(gunzip(&compressed).unwrap(), br#"{"ok":true}"#);
        compressed.extend_from_slice(b"trailing");
        assert!(gunzip(&compressed).is_err());
    }

    #[test]
    #[expect(
        deprecated,
        reason = "the Python fixture stores the expanded FIPS 203 key"
    )]
    fn official_python_response_fixture_decrypts() {
        use ml_kem::ExpandedKeyEncoding as _;

        let fixture: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/chutes-wire-fixture.json"
        ))
        .unwrap();
        let secret = BASE64
            .decode(fixture["response_secret_key_base64"].as_str().unwrap())
            .unwrap();
        let key = ResponseKey(
            DecapsulationKey::from_expanded_bytes(secret.as_slice().try_into().unwrap()).unwrap(),
        );
        let blob = BASE64
            .decode(fixture["response_blob_base64"].as_str().unwrap())
            .unwrap();
        let json: Value = serde_json::from_slice(&key.decrypt_response(&blob).unwrap()).unwrap();
        assert_eq!(json, fixture["expected"]);
    }
}
