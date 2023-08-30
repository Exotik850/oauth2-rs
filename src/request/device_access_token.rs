use super::{endpoint_request, endpoint_response};
use crate::types::{ClientSecret, TokenUrl};
use crate::*;

///
/// The request for an device access token from the authorization server.
///
/// See <https://tools.ietf.org/html/rfc8628#section-3.4>.
///
#[derive(Clone)]
pub struct DeviceAccessTokenRequest<'a, 'b, TR, TT, EF>
where
    TR: TokenResponse<TT>,
    TT: TokenType,
    EF: ExtraDeviceAuthorizationFields,
{
    pub auth_type: &'a AuthType,
    pub client_id: &'a ClientId,
    pub client_secret: Option<&'a ClientSecret>,
    pub extra_params: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    pub token_url: Option<&'a TokenUrl>,
    pub dev_auth_resp: &'a DeviceAuthorizationResponse<EF>,
    pub time_fn: Arc<dyn Fn() -> DateTime<Utc> + 'b + Send + Sync>,
    pub max_backoff_interval: Option<Duration>,
    pub(crate) _phantom: PhantomData<(TR, TT, EF)>,
}

impl<'a, 'b, TR, TT, EF> DeviceAccessTokenRequest<'a, 'b, TR, TT, EF>
where
    TR: TokenResponse<TT>,
    TT: TokenType,
    EF: ExtraDeviceAuthorizationFields,
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
    /// Specifies a function for returning the current time.
    ///
    /// This function is used while polling the authorization server.
    ///
    pub fn set_time_fn<T>(mut self, time_fn: T) -> Self
    where
        T: Fn() -> DateTime<Utc> + 'b + Send + Sync,
    {
        self.time_fn = Arc::new(time_fn);
        self
    }

    ///
    /// Sets the upper limit of the sleep interval to use for polling the token endpoint when the
    /// HTTP client returns an error (e.g., in case of connection timeout).
    ///
    pub fn set_max_backoff_interval(mut self, interval: Duration) -> Self {
        self.max_backoff_interval = Some(interval);
        self
    }

    ///
    /// Synchronously polls the authorization server for a response, waiting
    /// using a user defined sleep function.
    ///
    pub fn request<F, S, RE>(
        self,
        http_client: F,
        sleep_fn: S,
        timeout: Option<Duration>,
    ) -> Result<TR, RequestTokenError<RE, DeviceCodeErrorResponse>>
    where
        F: Fn(HttpRequest) -> Result<HttpResponse, RE>,
        S: Fn(Duration),
        RE: Error + 'static,
    {
        // Get the request timeout and starting interval
        let timeout_dt = self.compute_timeout(timeout)?;
        let mut interval = self.dev_auth_resp.interval();

        // Loop while requesting a token.
        loop {
            let now = (*self.time_fn)();
            if now > timeout_dt {
                break Err(RequestTokenError::ServerResponse(
                    DeviceCodeErrorResponse::new(
                        DeviceCodeErrorResponseType::ExpiredToken,
                        Some(String::from("This device code has expired.")),
                        None,
                    ),
                ));
            }

            match self.process_response(http_client(self.prepare_request()?), interval) {
                DeviceAccessTokenPollResult::ContinueWithNewPollInterval(new_interval) => {
                    interval = new_interval
                }
                DeviceAccessTokenPollResult::Done(res, _) => break res,
            }

            // Sleep here using the provided sleep function.
            sleep_fn(interval);
        }
    }

    ///
    /// Asynchronously sends the request to the authorization server and awaits a response.
    ///
    pub async fn request_async<C, F, S, SF, RE>(
        self,
        http_client: C,
        sleep_fn: S,
        timeout: Option<Duration>,
    ) -> Result<TR, RequestTokenError<RE, DeviceCodeErrorResponse>>
    where
        C: Fn(HttpRequest) -> F,
        F: Future<Output = Result<HttpResponse, RE>>,
        S: Fn(Duration) -> SF,
        SF: Future<Output = ()>,
        RE: Error + 'static,
    {
        // Get the request timeout and starting interval
        let timeout_dt = self.compute_timeout(timeout)?;
        let mut interval = self.dev_auth_resp.interval();

        // Loop while requesting a token.
        loop {
            let now = (*self.time_fn)();
            if now > timeout_dt {
                break Err(RequestTokenError::ServerResponse(
                    DeviceCodeErrorResponse::new(
                        DeviceCodeErrorResponseType::ExpiredToken,
                        Some(String::from("This device code has expired.")),
                        None,
                    ),
                ));
            }

            match self.process_response(http_client(self.prepare_request()?).await, interval) {
                DeviceAccessTokenPollResult::ContinueWithNewPollInterval(new_interval) => {
                    interval = new_interval
                }
                DeviceAccessTokenPollResult::Done(res, _) => break res,
            }

            // Sleep here using the provided sleep function.
            sleep_fn(interval).await;
        }
    }

    fn prepare_request<RE>(
        &self,
    ) -> Result<HttpRequest, RequestTokenError<RE, DeviceCodeErrorResponse>>
    where
        RE: Error + 'static,
    {
        Ok(endpoint_request(
            self.auth_type,
            self.client_id,
            self.client_secret,
            &self.extra_params,
            None,
            None,
            self.token_url
                .ok_or_else(|| RequestTokenError::Other("no token_url provided".to_string()))?
                .url(),
            vec![
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", self.dev_auth_resp.device_code.secret()),
            ],
        ))
    }

    fn process_response<RE>(
        &self,
        res: Result<HttpResponse, RE>,
        current_interval: Duration,
    ) -> DeviceAccessTokenPollResult<TR, RE, DeviceCodeErrorResponse, TT>
    where
        RE: Error + 'static,
    {
        let http_response = match res {
            Ok(inner) => inner,
            Err(_) => {
                // RFC 8628 requires a backoff in cases of connection timeout, but we can't
                // distinguish between connection timeouts and other HTTP client request errors
                // here. Set a maximum backoff so that the client doesn't effectively backoff
                // infinitely when there are network issues unrelated to server load.
                const DEFAULT_MAX_BACKOFF_INTERVAL: Duration = Duration::from_secs(10);
                let new_interval = std::cmp::min(
                    current_interval.checked_mul(2).unwrap_or(current_interval),
                    self.max_backoff_interval
                        .unwrap_or(DEFAULT_MAX_BACKOFF_INTERVAL),
                );
                return DeviceAccessTokenPollResult::ContinueWithNewPollInterval(new_interval);
            }
        };

        // Explicitly process the response with a DeviceCodeErrorResponse
        let res = endpoint_response::<RE, DeviceCodeErrorResponse, TR>(http_response);
        match res {
            // On a ServerResponse error, the error needs inspecting as a DeviceCodeErrorResponse
            // to work out whether a retry needs to happen.
            Err(RequestTokenError::ServerResponse(dcer)) => {
                match dcer.error {
                    // On AuthorizationPending, a retry needs to happen with the same poll interval.
                    DeviceCodeErrorResponseType::AuthorizationPending => {
                        DeviceAccessTokenPollResult::ContinueWithNewPollInterval(current_interval)
                    }
                    // On SlowDown, a retry needs to happen with a larger poll interval.
                    DeviceCodeErrorResponseType::SlowDown => {
                        DeviceAccessTokenPollResult::ContinueWithNewPollInterval(
                            current_interval + Duration::from_secs(5),
                        )
                    }

                    // On any other error, just return the error.
                    _ => DeviceAccessTokenPollResult::Done(
                        Err(RequestTokenError::ServerResponse(dcer)),
                        PhantomData,
                    ),
                }
            }

            // On any other success or failure, return the failure.
            res => DeviceAccessTokenPollResult::Done(res, PhantomData),
        }
    }

    fn compute_timeout<RE>(
        &self,
        timeout: Option<Duration>,
    ) -> Result<DateTime<Utc>, RequestTokenError<RE, DeviceCodeErrorResponse>>
    where
        RE: Error + 'static,
    {
        // Calculate the request timeout - if the user specified a timeout,
        // use that, otherwise use the value given by the device authorization
        // response.
        let timeout_dur = timeout.unwrap_or_else(|| self.dev_auth_resp.expires_in());
        let chrono_timeout = chrono::Duration::from_std(timeout_dur)
            .map_err(|_| RequestTokenError::Other("Failed to convert duration".to_string()))?;

        // Calculate the DateTime at which the request times out.
        let timeout_dt = (*self.time_fn)()
            .checked_add_signed(chrono_timeout)
            .ok_or_else(|| RequestTokenError::Other("Failed to calculate timeout".to_string()))?;

        Ok(timeout_dt)
    }
}
