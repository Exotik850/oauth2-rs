use super::{endpoint_request, endpoint_response_status_only};
use crate::types::{ClientSecret, RevocationUrl};
use crate::*;

///
/// A request to revoke a token via an [`RFC 7009`](https://tools.ietf.org/html/rfc7009#section-2.1) compatible
/// endpoint.
///
#[derive(Debug)]
pub struct RevocationRequest<'a, RT, TE>
where
    RT: RevocableToken,
    TE: ErrorResponse,
{
    pub token: RT,
    pub auth_type: &'a AuthType,
    pub client_id: &'a ClientId,
    pub client_secret: Option<&'a ClientSecret>,
    pub extra_params: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    pub revocation_url: &'a RevocationUrl,

    pub(crate) _phantom: PhantomData<(RT, TE)>,
}

impl<'a, RT, TE> RevocationRequest<'a, RT, TE>
where
    RT: RevocableToken,
    TE: ErrorResponse + 'static,
{
    ///
    /// Appends an extra param to the token revocation request.
    ///
    /// This method allows extensions to be used without direct support from
    /// this crate. If `name` conflicts with a parameter managed by this crate, the
    /// behavior is undefined. In particular, do not set parameters defined by
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749) or
    /// [RFC 7662](https://tools.ietf.org/html/rfc7662).
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

    fn prepare_request<RE>(self) -> Result<HttpRequest, RequestTokenError<RE, TE>>
    where
        RE: Error + 'static,
    {
        let mut params: Vec<(&str, &str)> = vec![("token", self.token.secret())];
        if let Some(type_hint) = self.token.type_hint() {
            params.push(("token_type_hint", type_hint));
        }

        Ok(endpoint_request(
            self.auth_type,
            self.client_id,
            self.client_secret,
            &self.extra_params,
            None,
            None,
            self.revocation_url.url(),
            params,
        ))
    }

    ///
    /// Synchronously sends the request to the authorization server and awaits a response.
    ///
    /// A successful response indicates that the server either revoked the token or the token was not known to the
    /// server.
    ///
    /// Error [`UnsupportedTokenType`](crate::revocation::RevocationErrorResponseType::UnsupportedTokenType) will be returned if the
    /// type of token type given is not supported by the server.
    ///
    pub fn request<F, RE>(self, http_client: F) -> Result<(), RequestTokenError<RE, TE>>
    where
        F: FnOnce(HttpRequest) -> Result<HttpResponse, RE>,
        RE: Error + 'static,
    {
        // From https://tools.ietf.org/html/rfc7009#section-2.2:
        //   "The content of the response body is ignored by the client as all
        //    necessary information is conveyed in the response code."
        http_client(self.prepare_request()?)
            .map_err(RequestTokenError::Request)
            .and_then(endpoint_response_status_only)
    }

    ///
    /// Asynchronously sends the request to the authorization server and returns a Future.
    ///
    pub async fn request_async<C, F, RE>(
        self,
        http_client: C,
    ) -> Result<(), RequestTokenError<RE, TE>>
    where
        C: FnOnce(HttpRequest) -> F,
        F: Future<Output = Result<HttpResponse, RE>>,
        RE: Error + 'static,
    {
        let http_request = self.prepare_request()?;
        let http_response = http_client(http_request)
            .await
            .map_err(RequestTokenError::Request)?;
        endpoint_response_status_only(http_response)
    }
}
