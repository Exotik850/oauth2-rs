use std::error::Error;
use std::fmt::Error as FormatterError;
use std::fmt::{Display, Formatter, Debug};

use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;

///
/// Server Error Response
///
/// This trait exists separately from the `StandardErrorResponse` struct
/// to support customization by clients, such as supporting interoperability with
/// non-standards-complaint OAuth2 providers
///
pub trait ErrorResponse: Debug + DeserializeOwned + Serialize {}

///
/// Error types enum.
///
/// NOTE: The serialization must return the `snake_case` representation of
/// this error type. This value must match the error type from the relevant OAuth 2.0 standards
/// (RFC 6749 or an extension).
///
pub trait ErrorResponseType: Debug + DeserializeOwned + Serialize {}

///
/// Error response returned by server after requesting an access token.
///
/// The fields in this structure are defined in
/// [Section 5.2 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.2). This
/// trait is parameterized by a `ErrorResponseType` to support error types specific to future OAuth2
/// authentication schemes and extensions.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct StandardErrorResponse<T> {
    ///
    /// REQUIRED. A single ASCII error code deserialized to the generic parameter
    /// `ErrorResponseType`.
    ///
    #[serde(bound = "T: ErrorResponseType")]
    pub error: T,
    ///
    /// OPTIONAL. Human-readable ASCII text providing additional information, used to assist
    /// the client developer in understanding the error that occurred. Values for this
    /// parameter MUST NOT include characters outside the set `%x20-21 / %x23-5B / %x5D-7E`.
    ///
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    ///
    /// OPTIONAL. URI identifying a human-readable web page with information about the error,
    /// used to provide the client developer with additional information about the error.
    /// Values for the "error_uri" parameter MUST conform to the URI-reference syntax and
    /// thus MUST NOT include characters outside the set `%x21 / %x23-5B / %x5D-7E`.
    ///
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
}

impl<T: ErrorResponseType> StandardErrorResponse<T> {
    ///
    /// Instantiate a new `ErrorResponse`.
    ///
    /// # Arguments
    ///
    /// * `error` - REQUIRED. A single ASCII error code deserialized to the generic parameter.
    ///   `ErrorResponseType`.
    /// * `error_description` - OPTIONAL. Human-readable ASCII text providing additional
    ///   information, used to assist the client developer in understanding the error that
    ///   occurred. Values for this parameter MUST NOT include characters outside the set
    ///   `%x20-21 / %x23-5B / %x5D-7E`.
    /// * `error_uri` - OPTIONAL. A URI identifying a human-readable web page with information
    ///   about the error used to provide the client developer with additional information about
    ///   the error. Values for the "error_uri" parameter MUST conform to the URI-reference
    ///   syntax and thus MUST NOT include characters outside the set `%x21 / %x23-5B / %x5D-7E`.
    ///
    pub fn new(error: T, error_description: Option<String>, error_uri: Option<String>) -> Self {
        Self {
            error,
            error_description,
            error_uri,
        }
    }
}

impl<T> ErrorResponse for StandardErrorResponse<T> where T: ErrorResponseType + 'static {}

impl<TE> Display for StandardErrorResponse<TE>
where
    TE: ErrorResponseType + Display,
{
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        let mut formatted = self.error.to_string();

        if let Some(error_description) = &self.error_description {
            formatted.push_str(": ");
            formatted.push_str(error_description);
        }

        if let Some(error_uri) = &self.error_uri {
            formatted.push_str(" / See ");
            formatted.push_str(error_uri);
        }

        write!(f, "{}", formatted)
    }
}

///
/// Error encountered while requesting access token.
///
#[derive(Debug, thiserror::Error)]
pub enum RequestTokenError<RE, T>
where
    RE: Error + 'static,
    T: ErrorResponse + 'static,
{
    ///
    /// Error response returned by authorization server. Contains the parsed `ErrorResponse`
    /// returned by the server.
    ///
    #[error("Server returned error response")]
    ServerResponse(T),
    ///
    /// An error occurred while sending the request or receiving the response (e.g., network
    /// connectivity failed).
    ///
    #[error("Request failed")]
    Request(#[source] RE),
    ///
    /// Failed to parse server response. Parse errors may occur while parsing either successful
    /// or error responses.
    ///
    #[error("Failed to parse server response")]
    Parse(
        #[source] serde_path_to_error::Error<serde_json::error::Error>,
        Vec<u8>,
    ),
    ///
    /// Some other type of error occurred (e.g., an unexpected server response).
    ///
    #[error("Other error: {}", _0)]
    Other(String),
}