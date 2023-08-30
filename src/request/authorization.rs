use crate::types::{AuthUrl, CsrfToken, RedirectUrl, ResponseType};
use crate::*;
use std::borrow::Cow;
use url::Url;

///
/// A request to the authorization endpoint
///
#[derive(Debug)]
pub struct AuthorizationRequest<'a> {
    pub auth_url: &'a AuthUrl,
    pub client_id: &'a ClientId,
    pub extra_params: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    pub pkce_challenge: Option<PkceCodeChallenge>,
    pub redirect_url: Option<Cow<'a, RedirectUrl>>,
    pub response_type: Cow<'a, str>,
    pub scopes: Vec<Cow<'a, Scope>>,
    pub state: CsrfToken,
}
impl<'a> AuthorizationRequest<'a> {
    ///
    /// Appends a new scope to the authorization URL.
    ///
    pub fn add_scope(mut self, scope: Scope) -> Self {
        self.scopes.push(Cow::Owned(scope));
        self
    }

    ///
    /// Appends a collection of scopes to the token request.
    ///
    pub fn add_scopes<I>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = Scope>,
    {
        self.scopes.extend(scopes.into_iter().map(Cow::Owned));
        self
    }

    ///
    /// Appends an extra param to the authorization URL.
    ///
    /// This method allows extensions to be used without direct support from
    /// this crate. If `name` conflicts with a parameter managed by this crate, the
    /// behavior is undefined. In particular, do not set parameters defined by
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749) or
    /// [RFC 7636](https://tools.ietf.org/html/rfc7636).
    ///
    /// # Security Warning
    ///
    /// Callers should follow the security recommendations for any OAuth2 extensions used with
    /// this function, which are beyond the scope of
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749).
    ///
    pub fn add_extra_param<N, V>(mut self, name: N, value: V) -> Self
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        self.extra_params.push((name.into(), value.into()));
        self
    }

    ///
    /// Enables the [Implicit Grant](https://tools.ietf.org/html/rfc6749#section-4.2) flow.
    ///
    pub fn use_implicit_flow(mut self) -> Self {
        self.response_type = "token".into();
        self
    }

    ///
    /// Enables custom flows other than the `code` and `token` (implicit flow) grant.
    ///
    pub fn set_response_type(mut self, response_type: &ResponseType) -> Self {
        self.response_type = (**response_type).to_owned().into();
        self
    }

    ///
    /// Enables the use of [Proof Key for Code Exchange](https://tools.ietf.org/html/rfc7636)
    /// (PKCE).
    ///
    /// PKCE is *highly recommended* for all public clients (i.e., those for which there
    /// is no client secret or for which the client secret is distributed with the client,
    /// such as in a native, mobile app, or browser app).
    ///
    pub fn set_pkce_challenge(mut self, pkce_code_challenge: PkceCodeChallenge) -> Self {
        self.pkce_challenge = Some(pkce_code_challenge);
        self
    }

    ///
    /// Overrides the `redirect_url` to the one specified.
    ///
    pub fn set_redirect_uri(mut self, redirect_url: Cow<'a, RedirectUrl>) -> Self {
        self.redirect_url = Some(redirect_url);
        self
    }

    ///
    /// Returns the full authorization URL and CSRF state for this authorization
    /// request.
    ///
    pub fn url(self) -> (Url, CsrfToken) {
        let scopes = self
            .scopes
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(" ");

        let url = {
            let mut pairs: Vec<(&str, &str)> = vec![
                ("response_type", self.response_type.as_ref()),
                ("client_id", &self.client_id),
                ("state", self.state.secret()),
            ];

            if let Some(ref pkce_challenge) = self.pkce_challenge {
                pairs.push(("code_challenge", &pkce_challenge.as_str()));
                pairs.push(("code_challenge_method", &pkce_challenge.method().as_str()));
            }

            if let Some(ref redirect_url) = self.redirect_url {
                pairs.push(("redirect_uri", redirect_url.as_str()));
            }

            if !scopes.is_empty() {
                pairs.push(("scope", &scopes));
            }

            let mut url: Url = self.auth_url.url().to_owned();

            url.query_pairs_mut()
                .extend_pairs(pairs.iter().map(|&(k, v)| (k, v)));

            url.query_pairs_mut()
                .extend_pairs(self.extra_params.iter().cloned());
            url
        };

        (url, self.state)
    }
}
