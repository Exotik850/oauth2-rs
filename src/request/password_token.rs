use super::{endpoint_request, endpoint_response};
use crate::types::{ClientSecret, ResourceOwnerPassword, ResourceOwnerUsername, Scope, TokenUrl};
use crate::*;

///
/// A request to exchange resource owner credentials for an access token.
///
/// See <https://tools.ietf.org/html/rfc6749#section-4.3>.
///
#[derive(Debug)]
pub struct PasswordTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse,
    TR: TokenResponse<TT>,
    TT: TokenType,
{
    pub auth_type: &'a AuthType,
    pub client_id: &'a ClientId,
    pub client_secret: Option<&'a ClientSecret>,
    pub extra_params: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    pub username: &'a ResourceOwnerUsername,
    pub password: &'a ResourceOwnerPassword,
    pub scopes: Vec<Cow<'a, Scope>>,
    pub token_url: Option<&'a TokenUrl>,
    pub(crate) _phantom: PhantomData<(TE, TR, TT)>,
}
impl<'a, TE, TR, TT> PasswordTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT>,
    TT: TokenType,
{
    ///
    /// Appends an extra param to the token request.
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
    /// Appends a new scope to the token request.
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
    /// Synchronously sends the request to the authorization server and awaits a response.
    ///
    pub fn request<F, RE>(self, http_client: F) -> Result<TR, RequestTokenError<RE, TE>>
    where
        F: FnOnce(HttpRequest) -> Result<HttpResponse, RE>,
        RE: Error + 'static,
    {
        http_client(self.prepare_request()?)
            .map_err(RequestTokenError::Request)
            .and_then(endpoint_response)
    }

    ///
    /// Asynchronously sends the request to the authorization server and awaits a response.
    ///
    pub async fn request_async<C, F, RE>(
        self,
        http_client: C,
    ) -> Result<TR, RequestTokenError<RE, TE>>
    where
        C: FnOnce(HttpRequest) -> F,
        F: Future<Output = Result<HttpResponse, RE>>,
        RE: Error + 'static,
    {
        let http_request = self.prepare_request()?;
        let http_response = http_client(http_request)
            .await
            .map_err(RequestTokenError::Request)?;
        endpoint_response(http_response)
    }

    fn prepare_request<RE>(&self) -> Result<HttpRequest, RequestTokenError<RE, TE>>
    where
        RE: Error + 'static,
    {
        Ok(endpoint_request(
            self.auth_type,
            self.client_id,
            self.client_secret,
            &self.extra_params,
            None,
            Some(&self.scopes),
            self.token_url
                .ok_or_else(|| RequestTokenError::Other("no token_url provided".to_string()))?
                .url(),
            vec![
                ("grant_type", "password"),
                ("username", self.username),
                ("password", self.password.secret()),
            ],
        ))
    }
}
