use super::{endpoint_request, endpoint_response};
use crate::types::{ClientSecret, DeviceAuthorizationUrl, Scope};
use crate::*;

///
/// The request for a set of verification codes from the authorization server.
///
/// See <https://tools.ietf.org/html/rfc8628#section-3.1>.
///
#[derive(Debug)]
pub struct DeviceAuthorizationRequest<'a, TE>
where
    TE: ErrorResponse,
{
    pub auth_type: &'a AuthType,
    pub client_id: &'a ClientId,
    pub client_secret: Option<&'a ClientSecret>,
    pub extra_params: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    pub scopes: Vec<Cow<'a, Scope>>,
    pub device_authorization_url: &'a DeviceAuthorizationUrl,
    pub(crate) _phantom: PhantomData<TE>,
}

impl<'a, TE> DeviceAuthorizationRequest<'a, TE>
where
    TE: ErrorResponse + 'static,
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

    fn prepare_request<RE>(self) -> Result<HttpRequest, RequestTokenError<RE, TE>>
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
            self.device_authorization_url.url(),
            vec![],
        ))
    }

    ///
    /// Synchronously sends the request to the authorization server and awaits a response.
    ///
    pub fn request<F, RE, EF>(
        self,
        http_client: F,
    ) -> Result<DeviceAuthorizationResponse<EF>, RequestTokenError<RE, TE>>
    where
        F: FnOnce(HttpRequest) -> Result<HttpResponse, RE>,
        RE: Error + 'static,
        EF: ExtraDeviceAuthorizationFields,
    {
        http_client(self.prepare_request()?)
            .map_err(RequestTokenError::Request)
            .and_then(endpoint_response)
    }

    ///
    /// Asynchronously sends the request to the authorization server and returns a Future.
    ///
    pub async fn request_async<C, F, RE, EF>(
        self,
        http_client: C,
    ) -> Result<DeviceAuthorizationResponse<EF>, RequestTokenError<RE, TE>>
    where
        C: FnOnce(HttpRequest) -> F,
        F: Future<Output = Result<HttpResponse, RE>>,
        RE: Error + 'static,
        EF: ExtraDeviceAuthorizationFields,
    {
        let http_request = self.prepare_request()?;
        let http_response = http_client(http_request)
            .await
            .map_err(RequestTokenError::Request)?;
        endpoint_response(http_response)
    }
}
