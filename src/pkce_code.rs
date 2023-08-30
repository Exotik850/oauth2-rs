use base64::Engine;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// This type intentionally does not implement Clone in order to make it difficult to reuse PKCE
// challenges across multiple requests.
crate::types::new_secret_type![
    ///
    /// Code Verifier used for [PKCE](https://tools.ietf.org/html/rfc7636) protection via the
    /// `code_verifier` parameter. The value must have a minimum length of 43 characters and a
    /// maximum length of 128 characters.  Each character must be ASCII alphanumeric or one of
    /// the characters "-" / "." / "_" / "~".
    ///
    #[derive(Deserialize, Serialize)]
    PkceCodeVerifier(String)
];

use std::fmt::{Debug, Formatter};

crate::types::new_type![
    ///
    /// Code Challenge Method used for [PKCE](https://tools.ietf.org/html/rfc7636) protection
    /// via the `code_challenge_method` parameter.
    ///
    #[derive(Deserialize, Serialize, Eq, Hash)]
    PkceCodeChallengeMethod(String)
];

///
/// Code Challenge used for [PKCE](https://tools.ietf.org/html/rfc7636) protection via the
/// `code_challenge` parameter.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PkceCodeChallenge {
    code_challenge: String,
    code_challenge_method: PkceCodeChallengeMethod,
}
impl PkceCodeChallenge {
    ///
    /// Generate a new random, base64-encoded SHA-256 PKCE code.
    ///
    pub fn new_random_sha256() -> (Self, PkceCodeVerifier) {
        Self::new_random_sha256_len(32)
    }

    ///
    /// Generate a new random, base64-encoded SHA-256 PKCE challenge code and verifier.
    ///
    /// # Arguments
    ///
    /// * `num_bytes` - Number of random bytes to generate, prior to base64-encoding.
    ///   The value must be in the range 32 to 96 inclusive in order to generate a verifier
    ///   with a suitable length.
    ///
    /// # Panics
    ///
    /// This method panics if the resulting PKCE code verifier is not of a suitable length
    /// to comply with [RFC 7636](https://tools.ietf.org/html/rfc7636).
    ///
    pub fn new_random_sha256_len(num_bytes: u32) -> (Self, PkceCodeVerifier) {
        let code_verifier = Self::new_random_len(num_bytes);
        (
            Self::from_code_verifier_sha256(&code_verifier),
            code_verifier,
        )
    }

    ///
    /// Generate a new random, base64-encoded PKCE code verifier.
    ///
    /// # Arguments
    ///
    /// * `num_bytes` - Number of random bytes to generate, prior to base64-encoding.
    ///   The value must be in the range 32 to 96 inclusive in order to generate a verifier
    ///   with a suitable length.
    ///
    /// # Panics
    ///
    /// This method panics if the resulting PKCE code verifier is not of a suitable length
    /// to comply with [RFC 7636](https://tools.ietf.org/html/rfc7636).
    ///
    fn new_random_len(num_bytes: u32) -> PkceCodeVerifier {
        // The RFC specifies that the code verifier must have "a minimum length of 43
        // characters and a maximum length of 128 characters".
        // This implies 32-96 octets of random data to be base64 encoded.
        assert!((32..=96).contains(&num_bytes));
        let random_bytes: Vec<u8> = (0..num_bytes).map(|_| thread_rng().gen::<u8>()).collect();
        PkceCodeVerifier::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes))
    }

    ///
    /// Generate a SHA-256 PKCE code challenge from the supplied PKCE code verifier.
    ///
    /// # Panics
    ///
    /// This method panics if the supplied PKCE code verifier is not of a suitable length
    /// to comply with [RFC 7636](https://tools.ietf.org/html/rfc7636).
    ///
    pub fn from_code_verifier_sha256(code_verifier: &PkceCodeVerifier) -> Self {
        // The RFC specifies that the code verifier must have "a minimum length of 43
        // characters and a maximum length of 128 characters".
        assert!(code_verifier.secret().len() >= 43 && code_verifier.secret().len() <= 128);

        let digest = Sha256::digest(code_verifier.secret().as_bytes());
        let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);

        Self {
            code_challenge,
            code_challenge_method: PkceCodeChallengeMethod::new("S256".to_string()),
        }
    }

    ///
    /// Generate a new random, base64-encoded PKCE code.
    /// Use is discouraged unless the endpoint does not support SHA-256.
    ///
    /// # Panics
    ///
    /// This method panics if the supplied PKCE code verifier is not of a suitable length
    /// to comply with [RFC 7636](https://tools.ietf.org/html/rfc7636).
    ///
    #[cfg(feature = "pkce-plain")]
    pub fn new_random_plain() -> (Self, PkceCodeVerifier) {
        let code_verifier = Self::new_random_len(32);
        (
            Self::from_code_verifier_plain(&code_verifier),
            code_verifier,
        )
    }

    ///
    /// Generate a plain PKCE code challenge from the supplied PKCE code verifier.
    /// Use is discouraged unless the endpoint does not support SHA-256.
    ///
    /// # Panics
    ///
    /// This method panics if the supplied PKCE code verifier is not of a suitable length
    /// to comply with [RFC 7636](https://tools.ietf.org/html/rfc7636).
    ///
    #[cfg(feature = "pkce-plain")]
    pub fn from_code_verifier_plain(code_verifier: &PkceCodeVerifier) -> Self {
        // The RFC specifies that the code verifier must have "a minimum length of 43
        // characters and a maximum length of 128 characters".
        assert!(code_verifier.secret().len() >= 43 && code_verifier.secret().len() <= 128);

        let code_challenge = code_verifier.secret().clone();

        Self {
            code_challenge,
            code_challenge_method: PkceCodeChallengeMethod::new("plain".to_string()),
        }
    }

    ///
    /// Returns the PKCE code challenge as a string.
    ///
    pub fn as_str(&self) -> &str {
        &self.code_challenge
    }

    ///
    /// Returns the PKCE code challenge method as a string.
    ///
    pub fn method(&self) -> &PkceCodeChallengeMethod {
        &self.code_challenge_method
    }
}
