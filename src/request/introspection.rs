use crate::types::{ClientSecret, IntrospectionUrl};
use crate::*;

use super::{endpoint_request, endpoint_response};

///
/// A request to introspect an access token.
///
/// See <https://tools.ietf.org/html/rfc7662#section-2.1>.
///
#[derive(Debug)]
pub struct IntrospectionRequest<'a, TE, TIR, TT>
where
    TE: ErrorResponse,
    TIR: TokenIntrospectionResponse<TT>,
    TT: TokenType,
{
    pub token: &'a AccessToken,
    pub token_type_hint: Option<Cow<'a, str>>,

    pub auth_type: &'a AuthType,
    pub client_id: &'a ClientId,
    pub client_secret: Option<&'a ClientSecret>,
    pub extra_params: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    pub introspection_url: &'a IntrospectionUrl,

    pub(crate) _phantom: PhantomData<(TE, TIR, TT)>,
}

impl<'a, TE, TIR, TT> IntrospectionRequest<'a, TE, TIR, TT>
where
    TE: ErrorResponse + 'static,
    TIR: TokenIntrospectionResponse<TT>,
    TT: TokenType,
{
    ///
    /// Sets the optional token_type_hint parameter.
    ///
    /// See <https://tools.ietf.org/html/rfc7662#section-2.1>.
    ///
    /// OPTIONAL.  A hint about the type of the token submitted for
    ///       introspection.  The protected resource MAY pass this parameter to
    ///       help the authorization server optimize the token lookup.  If the
    ///       server is unable to locate the token using the given hint, it MUST
    ///      extend its search across all of its supported token types.  An
    ///      authorization server MAY ignore this parameter, particularly if it
    ///      is able to detect the token type automatically.  Values for this
    ///      field are defined in the "OAuth Token Type Hints" registry defined
    ///      in OAuth Token Revocation [RFC7009](https://tools.ietf.org/html/rfc7009).
    ///
    pub fn set_token_type_hint<V>(mut self, value: V) -> Self
    where
        V: Into<Cow<'a, str>>,
    {
        self.token_type_hint = Some(value.into());

        self
    }

    ///
    /// Appends an extra param to the token introspection request.
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
        if let Some(ref token_type_hint) = self.token_type_hint {
            params.push(("token_type_hint", token_type_hint));
        }

        Ok(endpoint_request(
            self.auth_type,
            self.client_id,
            self.client_secret,
            &self.extra_params,
            None,
            None,
            self.introspection_url.url(),
            params,
        ))
    }

    ///
    /// Synchronously sends the request to the authorization server and awaits a response.
    ///
    pub fn request<F, RE>(self, http_client: F) -> Result<TIR, RequestTokenError<RE, TE>>
    where
        F: FnOnce(HttpRequest) -> Result<HttpResponse, RE>,
        RE: Error + 'static,
    {
        http_client(self.prepare_request()?)
            .map_err(RequestTokenError::Request)
            .and_then(endpoint_response)
    }

    ///
    /// Asynchronously sends the request to the authorization server and returns a Future.
    ///
    pub async fn request_async<C, F, RE>(
        self,
        http_client: C,
    ) -> Result<TIR, RequestTokenError<RE, TE>>
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
}
