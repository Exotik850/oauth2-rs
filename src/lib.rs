//!
//! An extensible, strongly-typed implementation of OAuth2
//! ([RFC 6749](https://tools.ietf.org/html/rfc6749)) including token introspection ([RFC 7662](https://tools.ietf.org/html/rfc7662))
//! and token revocation ([RFC 7009](https://tools.ietf.org/html/rfc7009)).
//!
//! # Contents
//! * [Importing `oauth2`: selecting an HTTP client interface](#importing-oauth2-selecting-an-http-client-interface)
//! * [Getting started: Authorization Code Grant w/ PKCE](#getting-started-authorization-code-grant-w-pkce)
//!   * [Example: Synchronous (blocking) API](#example-synchronous-blocking-api)
//!   * [Example: Asynchronous API](#example-asynchronous-api)
//! * [Implicit Grant](#implicit-grant)
//! * [Resource Owner Password Credentials Grant](#resource-owner-password-credentials-grant)
//! * [Client Credentials Grant](#client-credentials-grant)
//! * [Device Code Flow](#device-code-flow)
//! * [Other examples](#other-examples)
//!   * [Contributed Examples](#contributed-examples)
//!
//! # Importing `oauth2`: selecting an HTTP client interface
//!
//! This library offers a flexible HTTP client interface with two modes:
//!  * **Synchronous (blocking)**
//!  * **Asynchronous**
//!
//! For the HTTP client modes described above, the following HTTP client implementations can be
//! used:
//!  * **[`reqwest`]**
//!
//!    The `reqwest` HTTP client supports both the synchronous and asynchronous modes and is enabled
//!    by default.
//!
//!    Synchronous client: [`reqwest::http_client`]
//!
//!    Asynchronous client: [`reqwest::async_http_client`]
//!
//!  * **[`curl`]**
//!
//!    The `curl` HTTP client only supports the synchronous HTTP client mode and can be enabled in
//!    `Cargo.toml` via the `curl` feature flag.
//!
//!    Synchronous client: [`curl::http_client`]
//!
//! * **[`ureq`]**
//!
//!    The `ureq` HTTP client is a simple HTTP client with minimal dependencies. It only supports
//!    the synchronous HTTP client mode and can be enabled in `Cargo.toml` via the `ureq` feature
//!     flag.
//!
//!  * **Custom**
//!
//!    In addition to the clients above, users may define their own HTTP clients, which must accept
//!    an [`HttpRequest`] and return an [`HttpResponse`] or error. Users writing their own clients
//!    may wish to disable the default `reqwest` dependency by specifying
//!    `default-features = false` in `Cargo.toml` (replacing `...` with the desired version of this
//!    crate):
//!    ```toml
//!    oauth2 = { version = "...", default-features = false }
//!    ```
//!
//!    Synchronous HTTP clients should implement the following trait:
//!    ```rust,ignore
//!    FnOnce(HttpRequest) -> Result<HttpResponse, RE>
//!    where RE: std::error::Error + 'static
//!    ```
//!
//!    Asynchronous HTTP clients should implement the following trait:
//!    ```rust,ignore
//!    FnOnce(HttpRequest) -> F
//!    where
//!      F: Future<Output = Result<HttpResponse, RE>>,
//!      RE: std::error::Error + 'static
//!    ```
//!
//! # Getting started: Authorization Code Grant w/ PKCE
//!
//! This is the most common OAuth2 flow. PKCE is recommended whenever the OAuth2 client has no
//! client secret or has a client secret that cannot remain confidential (e.g., native, mobile, or
//! client-side web applications).
//!
//! ## Example: Synchronous (blocking) API
//!
//! This example works with `oauth2`'s default feature flags, which include `reqwest`.
//!
//! ```rust,no_run
//! use anyhow;
//! use oauth2::{
//!     AuthorizationCode,
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     CsrfToken,
//!     PkceCodeChallenge,
//!     RedirectUrl,
//!     Scope,
//!     TokenResponse,
//!     TokenUrl
//! };
//! use oauth2::basic::BasicClient;
//! use oauth2::reqwest::http_client;
//! use url::Url;
//!
//! # fn err_wrapper() -> Result<(), anyhow::Error> {
//! // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
//! // token URL.
//! let client =
//!     BasicClient::new(
//!         ClientId::new("client_id".to_string()),
//!         Some(ClientSecret::new("client_secret".to_string())),
//!         AuthUrl::new("http://authorize".to_string())?,
//!         Some(TokenUrl::new("http://token".to_string())?)
//!     )
//!     // Set the URL the user will be redirected to after the authorization process.
//!     .set_redirect_uri(RedirectUrl::new("http://redirect".to_string())?);
//!
//! // Generate a PKCE challenge.
//! let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
//!
//! // Generate the full authorization URL.
//! let (auth_url, csrf_token) = client
//!     .authorize_url(CsrfToken::new_random)
//!     // Set the desired scopes.
//!     .add_scope(Scope::new("read".to_string()))
//!     .add_scope(Scope::new("write".to_string()))
//!     // Set the PKCE code challenge.
//!     .set_pkce_challenge(pkce_challenge)
//!     .url();
//!
//! // This is the URL you should redirect the user to, in order to trigger the authorization
//! // process.
//! println!("Browse to: {}", auth_url);
//!
//! // Once the user has been redirected to the redirect URL, you'll have access to the
//! // authorization code. For security reasons, your code should verify that the `state`
//! // parameter returned by the server matches `csrf_state`.
//!
//! // Now you can trade it for an access token.
//! let token_result =
//!     client
//!         .exchange_code(AuthorizationCode::new("some authorization code".to_string()))
//!         // Set the PKCE code verifier.
//!         .set_pkce_verifier(pkce_verifier)
//!         .request(http_client)?;
//!
//! // Unwrapping token_result will either produce a Token or a RequestTokenError.
//! # Ok(())
//! # }
//! ```
//!
//! ## Example: Asynchronous API
//!
//! The example below uses async/await:
//!
//! ```rust,no_run
//! use anyhow;
//! use oauth2::{
//!     AuthorizationCode,
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     CsrfToken,
//!     PkceCodeChallenge,
//!     RedirectUrl,
//!     Scope,
//!     TokenResponse,
//!     TokenUrl
//! };
//! use oauth2::basic::BasicClient;
//! # #[cfg(feature = "reqwest")]
//! use oauth2::reqwest::async_http_client;
//! use url::Url;
//!
//! # #[cfg(feature = "reqwest")]
//! # async fn err_wrapper() -> Result<(), anyhow::Error> {
//! // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
//! // token URL.
//! let client =
//!     BasicClient::new(
//!         ClientId::new("client_id".to_string()),
//!         Some(ClientSecret::new("client_secret".to_string())),
//!         AuthUrl::new("http://authorize".to_string())?,
//!         Some(TokenUrl::new("http://token".to_string())?)
//!     )
//!     // Set the URL the user will be redirected to after the authorization process.
//!     .set_redirect_uri(RedirectUrl::new("http://redirect".to_string())?);
//!
//! // Generate a PKCE challenge.
//! let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
//!
//! // Generate the full authorization URL.
//! let (auth_url, csrf_token) = client
//!     .authorize_url(CsrfToken::new_random)
//!     // Set the desired scopes.
//!     .add_scope(Scope::new("read".to_string()))
//!     .add_scope(Scope::new("write".to_string()))
//!     // Set the PKCE code challenge.
//!     .set_pkce_challenge(pkce_challenge)
//!     .url();
//!
//! // This is the URL you should redirect the user to, in order to trigger the authorization
//! // process.
//! println!("Browse to: {}", auth_url);
//!
//! // Once the user has been redirected to the redirect URL, you'll have access to the
//! // authorization code. For security reasons, your code should verify that the `state`
//! // parameter returned by the server matches `csrf_state`.
//!
//! // Now you can trade it for an access token.
//! let token_result = client
//!     .exchange_code(AuthorizationCode::new("some authorization code".to_string()))
//!     // Set the PKCE code verifier.
//!     .set_pkce_verifier(pkce_verifier)
//!     .request_async(async_http_client)
//!     .await?;
//!
//! // Unwrapping token_result will either produce a Token or a RequestTokenError.
//! # Ok(())
//! # }
//! ```
//!
//! # Implicit Grant
//!
//! This flow fetches an access token directly from the authorization endpoint. Be sure to
//! understand the security implications of this flow before using it. In most cases, the
//! Authorization Code Grant flow is preferable to the Implicit Grant flow.
//!
//! ## Example
//!
//! ```rust,no_run
//! use anyhow;
//! use oauth2::{
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     CsrfToken,
//!     RedirectUrl,
//!     Scope
//! };
//! use oauth2::basic::BasicClient;
//! use url::Url;
//!
//! # fn err_wrapper() -> Result<(), anyhow::Error> {
//! let client =
//!     BasicClient::new(
//!         ClientId::new("client_id".to_string()),
//!         Some(ClientSecret::new("client_secret".to_string())),
//!         AuthUrl::new("http://authorize".to_string())?,
//!         None
//!     );
//!
//! // Generate the full authorization URL.
//! let (auth_url, csrf_token) = client
//!     .authorize_url(CsrfToken::new_random)
//!     .use_implicit_flow()
//!     .url();
//!
//! // This is the URL you should redirect the user to, in order to trigger the authorization
//! // process.
//! println!("Browse to: {}", auth_url);
//!
//! // Once the user has been redirected to the redirect URL, you'll have the access code.
//! // For security reasons, your code should verify that the `state` parameter returned by the
//! // server matches `csrf_state`.
//!
//! # Ok(())
//! # }
//! ```
//!
//! # Resource Owner Password Credentials Grant
//!
//! You can ask for a *password* access token by calling the `Client::exchange_password` method,
//! while including the username and password.
//!
//! ## Example
//!
//! ```rust,no_run
//! use anyhow;
//! use oauth2::{
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     ResourceOwnerPassword,
//!     ResourceOwnerUsername,
//!     Scope,
//!     TokenResponse,
//!     TokenUrl
//! };
//! use oauth2::basic::BasicClient;
//! use oauth2::reqwest::http_client;
//! use url::Url;
//!
//! # fn err_wrapper() -> Result<(), anyhow::Error> {
//! let client =
//!     BasicClient::new(
//!         ClientId::new("client_id".to_string()),
//!         Some(ClientSecret::new("client_secret".to_string())),
//!         AuthUrl::new("http://authorize".to_string())?,
//!         Some(TokenUrl::new("http://token".to_string())?)
//!     );
//!
//! let token_result =
//!     client
//!         .exchange_password(
//!             &ResourceOwnerUsername::new("user".to_string()),
//!             &ResourceOwnerPassword::new("pass".to_string())
//!         )
//!         .add_scope(Scope::new("read".to_string()))
//!         .request(http_client)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Client Credentials Grant
//!
//! You can ask for a *client credentials* access token by calling the
//! `Client::exchange_client_credentials` method.
//!
//! ## Example
//!
//! ```rust,no_run
//! use anyhow;
//! use oauth2::{
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     Scope,
//!     TokenResponse,
//!     TokenUrl
//! };
//! use oauth2::basic::BasicClient;
//! use oauth2::reqwest::http_client;
//! use url::Url;
//!
//! # fn err_wrapper() -> Result<(), anyhow::Error> {
//! let client =
//!     BasicClient::new(
//!         ClientId::new("client_id".to_string()),
//!         Some(ClientSecret::new("client_secret".to_string())),
//!         AuthUrl::new("http://authorize".to_string())?,
//!         Some(TokenUrl::new("http://token".to_string())?),
//!     );
//!
//! let token_result = client
//!     .exchange_client_credentials()
//!     .add_scope(Scope::new("read".to_string()))
//!     .request(http_client)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Device Code Flow
//!
//! Device Code Flow allows users to sign in on browserless or input-constrained
//! devices.  This is a two-stage process; first a user-code and verification
//! URL are obtained by using the `Client::exchange_client_credentials`
//! method. Those are displayed to the user, then are used in a second client
//! to poll the token endpoint for a token.
//!
//! ## Example
//!
//! ```rust,no_run
//! use anyhow;
//! use oauth2::{
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     DeviceAuthorizationUrl,
//!     Scope,
//!     TokenResponse,
//!     TokenUrl
//! };
//! use oauth2::basic::BasicClient;
//! use oauth2::devicecode::StandardDeviceAuthorizationResponse;
//! use oauth2::reqwest::http_client;
//! use url::Url;
//!
//! # fn err_wrapper() -> Result<(), anyhow::Error> {
//! let device_auth_url = DeviceAuthorizationUrl::new("http://deviceauth".to_string())?;
//! let client =
//!     BasicClient::new(
//!         ClientId::new("client_id".to_string()),
//!         Some(ClientSecret::new("client_secret".to_string())),
//!         AuthUrl::new("http://authorize".to_string())?,
//!         Some(TokenUrl::new("http://token".to_string())?),
//!     )
//!     .set_device_authorization_url(device_auth_url);
//!
//! let details: StandardDeviceAuthorizationResponse = client
//!     .exchange_device_code()?
//!     .add_scope(Scope::new("read".to_string()))
//!     .request(http_client)?;
//!
//! println!(
//!     "Open this URL in your browser:\n{}\nand enter the code: {}",
//!     details.verification_uri().to_string(),
//!     details.user_code().secret().to_string()
//! );
//!
//! let token_result =
//!     client
//!     .exchange_device_access_token(&details)
//!     .request(http_client, std::thread::sleep, None)?;
//!
//! # Ok(())
//! # }
//! ```
//!
//! # Other examples
//!
//! More specific implementations are available as part of the examples:
//!
//! - [Google](https://github.com/ramosbugs/oauth2-rs/blob/main/examples/google.rs) (includes token revocation)
//! - [Github](https://github.com/ramosbugs/oauth2-rs/blob/main/examples/github.rs)
//! - [Microsoft Device Code Flow (async)](https://github.com/ramosbugs/oauth2-rs/blob/main/examples/microsoft_devicecode.rs)
//! - [Microsoft Graph](https://github.com/ramosbugs/oauth2-rs/blob/main/examples/msgraph.rs)
//! - [Wunderlist](https://github.com/ramosbugs/oauth2-rs/blob/main/examples/wunderlist.rs)
//!
//! ## Contributed Examples
//!
//! - [`actix-web-oauth2`](https://github.com/pka/actix-web-oauth2) (version 2.x of this crate)
//!
use std::borrow::Cow;
use std::error::Error;
use std::fmt::Error as FormatterError;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use chrono::serde::ts_seconds_option;
use chrono::{DateTime, Utc};
use http::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::status::StatusCode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::{form_urlencoded, Url};

use crate::devicecode::DeviceAccessTokenPollResult;

mod client;
mod pkce_code;
pub mod request;
pub use client::Client;

///
/// Basic OAuth2 implementation with no extensions
/// ([RFC 6749](https://tools.ietf.org/html/rfc6749)).
///
pub mod basic;

///
/// HTTP client backed by the [curl](https://crates.io/crates/curl) crate.
/// Requires "curl" feature.
///
#[cfg(all(feature = "curl", not(target_arch = "wasm32")))]
pub mod curl;

#[cfg(all(feature = "curl", target_arch = "wasm32"))]
compile_error!("wasm32 is not supported with the `curl` feature. Use the `reqwest` backend or a custom backend for wasm32 support");

///
/// Device Code Flow OAuth2 implementation
/// ([RFC 8628](https://tools.ietf.org/html/rfc8628)).
///
pub mod devicecode;

///
/// OAuth 2.0 Token Revocation implementation
/// ([RFC 7009](https://tools.ietf.org/html/rfc7009)).
///
pub mod revocation;

///
/// Helper methods used by OAuth2 implementations/extensions.
///
pub mod helpers;

///
/// HTTP client backed by the [reqwest](https://crates.io/crates/reqwest) crate.
/// Requires "reqwest" feature.
///
#[cfg(feature = "reqwest")]
pub mod reqwest;

#[cfg(test)]
mod tests;

pub mod types;

///
/// HTTP client backed by the [ureq](https://crates.io/crates/ureq) crate.
/// Requires "ureq" feature.
///
#[cfg(feature = "ureq")]
pub mod ureq;

///
/// Public re-exports of types used for HTTP client interfaces.
///
pub use http;
pub use url;

pub use devicecode::{
    DeviceAuthorizationResponse, DeviceCodeErrorResponse, DeviceCodeErrorResponseType,
    EmptyExtraDeviceAuthorizationFields, ExtraDeviceAuthorizationFields,
    StandardDeviceAuthorizationResponse,
};

pub use pkce_code::{PkceCodeChallenge, PkceCodeChallengeMethod, PkceCodeVerifier};
pub use types::{AccessToken, ClientId, RefreshToken, Scope};

pub use revocation::{RevocableToken, RevocationErrorResponseType, StandardRevocableToken};

const CONTENT_TYPE_JSON: &str = "application/json";
const CONTENT_TYPE_FORMENCODED: &str = "application/x-www-form-urlencoded";

///
/// There was a problem configuring the request.
///
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ConfigurationError {
    ///
    /// The endpoint URL tp be contacted is missing.
    ///
    #[error("No {0} endpoint URL specified")]
    MissingUrl(&'static str),
    ///
    /// The endpoint URL to be contacted MUST be HTTPS.
    ///
    #[error("Scheme for {0} endpoint URL must be HTTPS")]
    InsecureUrl(&'static str),
}

///
/// Indicates whether requests to the authorization server should use basic authentication or
/// include the parameters in the request body for requests in which either is valid.
///
/// The default AuthType is *BasicAuth*, following the recommendation of
/// [Section 2.3.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-2.3.1).
///
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum AuthType {
    /// The client_id and client_secret (if set) will be included as part of the request body.
    RequestBody,
    /// The client_id and client_secret will be included using the basic auth authentication scheme.
    BasicAuth,
}

///
/// An HTTP request.
///
#[derive(Clone, Debug)]
pub struct HttpRequest {
    // These are all owned values so that the request can safely be passed between
    // threads.
    /// URL to which the HTTP request is being made.
    pub url: Url,
    /// HTTP request method for this request.
    pub method: http::method::Method,
    /// HTTP request headers to send.
    pub headers: HeaderMap,
    /// HTTP request body (typically for POST requests only).
    pub body: Vec<u8>,
}

///
/// An HTTP response.
///
#[derive(Clone, Debug)]
pub struct HttpResponse {
    /// HTTP status code returned by the server.
    pub status_code: http::status::StatusCode,
    /// HTTP response headers returned by the server.
    pub headers: HeaderMap,
    /// HTTP response body returned by the server.
    pub body: Vec<u8>,
}

fn check_response_body<RE, TE>(
    http_response: &HttpResponse,
) -> Result<(), RequestTokenError<RE, TE>>
where
    RE: Error + 'static,
    TE: ErrorResponse,
{
    // Validate that the response Content-Type is JSON.
    http_response
        .headers
        .get(CONTENT_TYPE)
        .map_or(Ok(()), |content_type|
            // Section 3.1.1.1 of RFC 7231 indicates that media types are case insensitive and
            // may be followed by optional whitespace and/or a parameter (e.g., charset).
            // See https://tools.ietf.org/html/rfc7231#section-3.1.1.1.
            if content_type.to_str().ok().filter(|ct| ct.to_lowercase().starts_with(CONTENT_TYPE_JSON)).is_none() {
                Err(
                    RequestTokenError::Other(
                        format!(
                            "Unexpected response Content-Type: {:?}, should be `{}`",
                            content_type,
                            CONTENT_TYPE_JSON
                        )
                    )
                )
            } else {
                Ok(())
            }
        )?;

    if http_response.body.is_empty() {
        return Err(RequestTokenError::Other(
            "Server returned empty response body".to_string(),
        ));
    }

    Ok(())
}

///
/// Trait for OAuth2 access tokens.
///
pub trait TokenType: Clone + DeserializeOwned + Debug + PartialEq + Serialize {}

///
/// Trait for adding extra fields to the `TokenResponse`.
///
pub trait ExtraTokenFields: DeserializeOwned + Debug + Serialize {}

///
/// Empty (default) extra token fields.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EmptyExtraTokenFields {}
impl ExtraTokenFields for EmptyExtraTokenFields {}

///
/// Common methods shared by all OAuth2 token implementations.
///
/// The methods in this trait are defined in
/// [Section 5.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.1). This trait exists
/// separately from the `StandardTokenResponse` struct to support customization by clients,
/// such as supporting interoperability with non-standards-complaint OAuth2 providers.
///
pub trait TokenResponse<TT>: Debug + DeserializeOwned + Serialize
where
    TT: TokenType,
{
    ///
    /// REQUIRED. The access token issued by the authorization server.
    ///
    fn access_token(&self) -> &AccessToken;
    ///
    /// REQUIRED. The type of the token issued as described in
    /// [Section 7.1](https://tools.ietf.org/html/rfc6749#section-7.1).
    /// Value is case insensitive and deserialized to the generic `TokenType` parameter.
    ///
    fn token_type(&self) -> &TT;
    ///
    /// RECOMMENDED. The lifetime in seconds of the access token. For example, the value 3600
    /// denotes that the access token will expire in one hour from the time the response was
    /// generated. If omitted, the authorization server SHOULD provide the expiration time via
    /// other means or document the default value.
    ///
    fn expires_in(&self) -> Option<Duration>;
    ///
    /// OPTIONAL. The refresh token, which can be used to obtain new access tokens using the same
    /// authorization grant as described in
    /// [Section 6](https://tools.ietf.org/html/rfc6749#section-6).
    ///
    fn refresh_token(&self) -> Option<&RefreshToken>;
    ///
    /// OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED. The
    /// scope of the access token as described by
    /// [Section 3.3](https://tools.ietf.org/html/rfc6749#section-3.3). If included in the response,
    /// this space-delimited field is parsed into a `Vec` of individual scopes. If omitted from
    /// the response, this field is `None`.
    ///
    fn scopes(&self) -> Option<&Vec<Scope>>;
}

///
/// Standard OAuth2 token response.
///
/// This struct includes the fields defined in
/// [Section 5.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.1), as well as
/// extensions defined by the `EF` type parameter.
///
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StandardTokenResponse<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType,
{
    pub access_token: AccessToken,
    #[serde(bound = "TT: TokenType")]
    #[serde(deserialize_with = "helpers::deserialize_untagged_enum_case_insensitive")]
    token_type: TT,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<RefreshToken>,
    #[serde(rename = "scope")]
    #[serde(deserialize_with = "helpers::deserialize_space_delimited_vec")]
    #[serde(serialize_with = "helpers::serialize_space_delimited_vec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    scopes: Option<Vec<Scope>>,

    #[serde(bound = "EF: ExtraTokenFields")]
    #[serde(flatten)]
    extra_fields: EF,
}
impl<EF, TT> StandardTokenResponse<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType,
{
    ///
    /// Instantiate a new OAuth2 token response.
    ///
    pub fn new(access_token: AccessToken, token_type: TT, extra_fields: EF) -> Self {
        Self {
            access_token,
            token_type,
            expires_in: None,
            refresh_token: None,
            scopes: None,
            extra_fields,
        }
    }

    ///
    /// Set the `access_token` field.
    ///
    pub fn set_access_token(&mut self, access_token: AccessToken) {
        self.access_token = access_token;
    }

    ///
    /// Set the `token_type` field.
    ///
    pub fn set_token_type(&mut self, token_type: TT) {
        self.token_type = token_type;
    }

    ///
    /// Set the `expires_in` field.
    ///
    pub fn set_expires_in(&mut self, expires_in: Option<&Duration>) {
        self.expires_in = expires_in.map(Duration::as_secs);
    }

    ///
    /// Set the `refresh_token` field.
    ///
    pub fn set_refresh_token(&mut self, refresh_token: Option<RefreshToken>) {
        self.refresh_token = refresh_token;
    }

    ///
    /// Set the `scopes` field.
    ///
    pub fn set_scopes(&mut self, scopes: Option<Vec<Scope>>) {
        self.scopes = scopes;
    }

    ///
    /// Extra fields defined by the client application.
    ///
    pub fn extra_fields(&self) -> &EF {
        &self.extra_fields
    }

    ///
    /// Set the extra fields defined by the client application.
    ///
    pub fn set_extra_fields(&mut self, extra_fields: EF) {
        self.extra_fields = extra_fields;
    }
}
impl<EF, TT> TokenResponse<TT> for StandardTokenResponse<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType,
{
    ///
    /// REQUIRED. The access token issued by the authorization server.
    ///
    fn access_token(&self) -> &AccessToken {
        &self.access_token
    }
    ///
    /// REQUIRED. The type of the token issued as described in
    /// [Section 7.1](https://tools.ietf.org/html/rfc6749#section-7.1).
    /// Value is case insensitive and deserialized to the generic `TokenType` parameter.
    ///
    fn token_type(&self) -> &TT {
        &self.token_type
    }
    ///
    /// RECOMMENDED. The lifetime in seconds of the access token. For example, the value 3600
    /// denotes that the access token will expire in one hour from the time the response was
    /// generated. If omitted, the authorization server SHOULD provide the expiration time via
    /// other means or document the default value.
    ///
    fn expires_in(&self) -> Option<Duration> {
        self.expires_in.map(Duration::from_secs)
    }
    ///
    /// OPTIONAL. The refresh token, which can be used to obtain new access tokens using the same
    /// authorization grant as described in
    /// [Section 6](https://tools.ietf.org/html/rfc6749#section-6).
    ///
    fn refresh_token(&self) -> Option<&RefreshToken> {
        self.refresh_token.as_ref()
    }
    ///
    /// OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED. The
    /// scope of the access token as described by
    /// [Section 3.3](https://tools.ietf.org/html/rfc6749#section-3.3). If included in the response,
    /// this space-delimited field is parsed into a `Vec` of individual scopes. If omitted from
    /// the response, this field is `None`.
    ///
    fn scopes(&self) -> Option<&Vec<Scope>> {
        self.scopes.as_ref()
    }
}

///
/// Common methods shared by all OAuth2 token introspection implementations.
///
/// The methods in this trait are defined in
/// [Section 2.2 of RFC 7662](https://tools.ietf.org/html/rfc7662#section-2.2). This trait exists
/// separately from the `StandardTokenIntrospectionResponse` struct to support customization by
/// clients, such as supporting interoperability with non-standards-complaint OAuth2 providers.
///
pub trait TokenIntrospectionResponse<TT>: Debug + DeserializeOwned + Serialize
where
    TT: TokenType,
{
    ///
    /// REQUIRED.  Boolean indicator of whether or not the presented token
    /// is currently active.  The specifics of a token's "active" state
    /// will vary depending on the implementation of the authorization
    /// server and the information it keeps about its tokens, but a "true"
    /// value return for the "active" property will generally indicate
    /// that a given token has been issued by this authorization server,
    /// has not been revoked by the resource owner, and is within its
    /// given time window of validity (e.g., after its issuance time and
    /// before its expiration time).
    ///
    fn active(&self) -> bool;
    ///
    ///
    /// OPTIONAL.  A JSON string containing a space-separated list of
    /// scopes associated with this token, in the format described in
    /// [Section 3.3 of RFC 7662](https://tools.ietf.org/html/rfc7662#section-3.3).
    /// If included in the response,
    /// this space-delimited field is parsed into a `Vec` of individual scopes. If omitted from
    /// the response, this field is `None`.
    ///
    fn scopes(&self) -> Option<&Vec<Scope>>;
    ///
    /// OPTIONAL.  Client identifier for the OAuth 2.0 client that
    /// requested this token.
    ///
    fn client_id(&self) -> Option<&ClientId>;
    ///
    /// OPTIONAL.  Human-readable identifier for the resource owner who
    /// authorized this token.
    ///
    fn username(&self) -> Option<&str>;
    ///
    /// OPTIONAL.  Type of the token as defined in
    /// [Section 5.1 of RFC 7662](https://tools.ietf.org/html/rfc7662#section-5.1).
    /// Value is case insensitive and deserialized to the generic `TokenType` parameter.
    ///
    fn token_type(&self) -> Option<&TT>;
    ///
    /// OPTIONAL.  Integer timestamp, measured in the number of seconds
    /// since January 1 1970 UTC, indicating when this token will expire,
    /// as defined in JWT [RFC7519](https://tools.ietf.org/html/rfc7519).
    ///
    fn exp(&self) -> Option<DateTime<Utc>>;
    ///
    /// OPTIONAL.  Integer timestamp, measured in the number of seconds
    /// since January 1 1970 UTC, indicating when this token was
    /// originally issued, as defined in JWT [RFC7519](https://tools.ietf.org/html/rfc7519).
    ///
    fn iat(&self) -> Option<DateTime<Utc>>;
    ///
    /// OPTIONAL.  Integer timestamp, measured in the number of seconds
    /// since January 1 1970 UTC, indicating when this token is not to be
    /// used before, as defined in JWT [RFC7519](https://tools.ietf.org/html/rfc7519).
    ///
    fn nbf(&self) -> Option<DateTime<Utc>>;
    ///
    /// OPTIONAL.  Subject of the token, as defined in JWT [RFC7519](https://tools.ietf.org/html/rfc7519).
    /// Usually a machine-readable identifier of the resource owner who
    /// authorized this token.
    ///
    fn sub(&self) -> Option<&str>;
    ///
    /// OPTIONAL.  Service-specific string identifier or list of string
    /// identifiers representing the intended audience for this token, as
    /// defined in JWT [RFC7519](https://tools.ietf.org/html/rfc7519).
    ///
    fn aud(&self) -> Option<&Vec<String>>;
    ///
    /// OPTIONAL.  String representing the issuer of this token, as
    /// defined in JWT [RFC7519](https://tools.ietf.org/html/rfc7519).
    ///
    fn iss(&self) -> Option<&str>;
    ///
    /// OPTIONAL.  String identifier for the token, as defined in JWT
    /// [RFC7519](https://tools.ietf.org/html/rfc7519).
    ///
    fn jti(&self) -> Option<&str>;
}

///
/// Standard OAuth2 token introspection response.
///
/// This struct includes the fields defined in
/// [Section 2.2 of RFC 7662](https://tools.ietf.org/html/rfc7662#section-2.2), as well as
/// extensions defined by the `EF` type parameter.
///
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StandardTokenIntrospectionResponse<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType + 'static,
{
    active: bool,
    #[serde(rename = "scope")]
    #[serde(deserialize_with = "helpers::deserialize_space_delimited_vec")]
    #[serde(serialize_with = "helpers::serialize_space_delimited_vec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    scopes: Option<Vec<Scope>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<ClientId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(
        bound = "TT: TokenType",
        skip_serializing_if = "Option::is_none",
        deserialize_with = "helpers::deserialize_untagged_enum_case_insensitive",
        default = "none_field"
    )]
    token_type: Option<TT>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_seconds_option")]
    #[serde(default)]
    exp: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_seconds_option")]
    #[serde(default)]
    iat: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_seconds_option")]
    #[serde(default)]
    nbf: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(deserialize_with = "helpers::deserialize_optional_string_or_vec_string")]
    aud: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<String>,

    #[serde(bound = "EF: ExtraTokenFields")]
    #[serde(flatten)]
    extra_fields: EF,
}

fn none_field<T>() -> Option<T> {
    None
}

impl<EF, TT> StandardTokenIntrospectionResponse<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType,
{
    ///
    /// Instantiate a new OAuth2 token introspection response.
    ///
    pub fn new(active: bool, extra_fields: EF) -> Self {
        Self {
            active,

            scopes: None,
            client_id: None,
            username: None,
            token_type: None,
            exp: None,
            iat: None,
            nbf: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
            extra_fields,
        }
    }

    ///
    /// Sets the `set_active` field.
    ///
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }
    ///
    /// Sets the `set_scopes` field.
    ///
    pub fn set_scopes(&mut self, scopes: Option<Vec<Scope>>) {
        self.scopes = scopes;
    }
    ///
    /// Sets the `set_client_id` field.
    ///
    pub fn set_client_id(&mut self, client_id: Option<ClientId>) {
        self.client_id = client_id;
    }
    ///
    /// Sets the `set_username` field.
    ///
    pub fn set_username(&mut self, username: Option<String>) {
        self.username = username;
    }
    ///
    /// Sets the `set_token_type` field.
    ///
    pub fn set_token_type(&mut self, token_type: Option<TT>) {
        self.token_type = token_type;
    }
    ///
    /// Sets the `set_exp` field.
    ///
    pub fn set_exp(&mut self, exp: Option<DateTime<Utc>>) {
        self.exp = exp;
    }
    ///
    /// Sets the `set_iat` field.
    ///
    pub fn set_iat(&mut self, iat: Option<DateTime<Utc>>) {
        self.iat = iat;
    }
    ///
    /// Sets the `set_nbf` field.
    ///
    pub fn set_nbf(&mut self, nbf: Option<DateTime<Utc>>) {
        self.nbf = nbf;
    }
    ///
    /// Sets the `set_sub` field.
    ///
    pub fn set_sub(&mut self, sub: Option<String>) {
        self.sub = sub;
    }
    ///
    /// Sets the `set_aud` field.
    ///
    pub fn set_aud(&mut self, aud: Option<Vec<String>>) {
        self.aud = aud;
    }
    ///
    /// Sets the `set_iss` field.
    ///
    pub fn set_iss(&mut self, iss: Option<String>) {
        self.iss = iss;
    }
    ///
    /// Sets the `set_jti` field.
    ///
    pub fn set_jti(&mut self, jti: Option<String>) {
        self.jti = jti;
    }
    ///
    /// Extra fields defined by the client application.
    ///
    pub fn extra_fields(&self) -> &EF {
        &self.extra_fields
    }
    ///
    /// Sets the `set_extra_fields` field.
    ///
    pub fn set_extra_fields(&mut self, extra_fields: EF) {
        self.extra_fields = extra_fields;
    }
}
impl<EF, TT> TokenIntrospectionResponse<TT> for StandardTokenIntrospectionResponse<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType,
{
    fn active(&self) -> bool {
        self.active
    }

    fn scopes(&self) -> Option<&Vec<Scope>> {
        self.scopes.as_ref()
    }

    fn client_id(&self) -> Option<&ClientId> {
        self.client_id.as_ref()
    }

    fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    fn token_type(&self) -> Option<&TT> {
        self.token_type.as_ref()
    }

    fn exp(&self) -> Option<DateTime<Utc>> {
        self.exp
    }

    fn iat(&self) -> Option<DateTime<Utc>> {
        self.iat
    }

    fn nbf(&self) -> Option<DateTime<Utc>> {
        self.nbf
    }

    fn sub(&self) -> Option<&str> {
        self.sub.as_deref()
    }

    fn aud(&self) -> Option<&Vec<String>> {
        self.aud.as_ref()
    }

    fn iss(&self) -> Option<&str> {
        self.iss.as_deref()
    }

    fn jti(&self) -> Option<&str> {
        self.jti.as_deref()
    }
}

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
    error: T,
    ///
    /// OPTIONAL. Human-readable ASCII text providing additional information, used to assist
    /// the client developer in understanding the error that occurred. Values for this
    /// parameter MUST NOT include characters outside the set `%x20-21 / %x23-5B / %x5D-7E`.
    ///
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
    ///
    /// OPTIONAL. URI identifying a human-readable web page with information about the error,
    /// used to provide the client developer with additional information about the error.
    /// Values for the "error_uri" parameter MUST conform to the URI-reference syntax and
    /// thus MUST NOT include characters outside the set `%x21 / %x23-5B / %x5D-7E`.
    ///
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    error_uri: Option<String>,
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
