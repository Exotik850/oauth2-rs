mod authorization;
mod client_credentials;
mod code_token;
mod device_access_token;
mod device_authorization;
mod introspection;
mod password_token;
mod refresh_token;
mod revocation;

use crate::{
    types::{ClientSecret, RedirectUrl},
    *,
};

pub use {
    authorization::AuthorizationRequest, client_credentials::ClientCredentialsTokenRequest,
    code_token::CodeTokenRequest, device_access_token::DeviceAccessTokenRequest,
    device_authorization::DeviceAuthorizationRequest, introspection::IntrospectionRequest,
    password_token::PasswordTokenRequest, refresh_token::RefreshTokenRequest,
    revocation::RevocationRequest,
};

#[allow(clippy::too_many_arguments)]
fn endpoint_request<'a>(
    auth_type: &'a AuthType,
    client_id: &'a ClientId,
    client_secret: Option<&'a ClientSecret>,
    extra_params: &'a [(Cow<'a, str>, Cow<'a, str>)],
    redirect_url: Option<Cow<'a, RedirectUrl>>,
    scopes: Option<&'a Vec<Cow<'a, Scope>>>,
    url: &'a Url,
    params: Vec<(&'a str, &'a str)>,
) -> HttpRequest {
    let mut headers = HeaderMap::new();
    headers.append(ACCEPT, HeaderValue::from_static(CONTENT_TYPE_JSON));
    headers.append(
        CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE_FORMENCODED),
    );

    let scopes_opt = scopes.and_then(|scopes| {
        if !scopes.is_empty() {
            Some(
                scopes
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        } else {
            None
        }
    });

    let mut params: Vec<(&str, &str)> = params;
    if let Some(ref scopes) = scopes_opt {
        params.push(("scope", scopes));
    }

    // FIXME: add support for auth extensions? e.g., client_secret_jwt and private_key_jwt
    match (auth_type, client_secret) {
        // Basic auth only makes sense when a client secret is provided. Otherwise, always pass the
        // client ID in the request body.
        (AuthType::BasicAuth, Some(secret)) => {
            // Section 2.3.1 of RFC 6749 requires separately url-encoding the id and secret
            // before using them as HTTP Basic auth username and password. Note that this is
            // not standard for ordinary Basic auth, so curl won't do it for us.
            let urlencoded_id: String =
                form_urlencoded::byte_serialize(client_id.as_bytes()).collect();
            let urlencoded_secret: String =
                form_urlencoded::byte_serialize(secret.secret().as_bytes()).collect();
            let b64_credential = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", &urlencoded_id, urlencoded_secret));
            headers.append(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Basic {}", &b64_credential)).unwrap(),
            );
        }
        (AuthType::RequestBody, _) | (AuthType::BasicAuth, None) => {
            params.push(("client_id", client_id));
            if let Some(client_secret) = client_secret {
                params.push(("client_secret", client_secret.secret()));
            }
        }
    }

    if let Some(ref redirect_url) = redirect_url {
        params.push(("redirect_uri", redirect_url.as_str()));
    }

    params.extend_from_slice(
        extra_params
            .iter()
            .map(|(k, v)| (k.as_ref(), v.as_ref()))
            .collect::<Vec<_>>()
            .as_slice(),
    );

    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish()
        .into_bytes();

    HttpRequest {
        url: url.to_owned(),
        method: http::method::Method::POST,
        headers,
        body,
    }
}

fn endpoint_response<RE, TE, DO>(
    http_response: HttpResponse,
) -> Result<DO, RequestTokenError<RE, TE>>
where
    RE: Error + 'static,
    TE: ErrorResponse,
    DO: DeserializeOwned,
{
    check_response_status(&http_response)?;

    check_response_body(&http_response)?;

    let response_body = http_response.body.as_slice();
    serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_slice(response_body))
        .map_err(|e| RequestTokenError::Parse(e, response_body.to_vec()))
}

fn endpoint_response_status_only<RE, TE>(
    http_response: HttpResponse,
) -> Result<(), RequestTokenError<RE, TE>>
where
    RE: Error + 'static,
    TE: ErrorResponse,
{
    check_response_status(&http_response)
}

fn check_response_status<RE, TE>(
    http_response: &HttpResponse,
) -> Result<(), RequestTokenError<RE, TE>>
where
    RE: Error + 'static,
    TE: ErrorResponse,
{
    if http_response.status_code != StatusCode::OK {
        let reason = http_response.body.as_slice();
        if reason.is_empty() {
            return Err(RequestTokenError::Other(
                "Server returned empty error response".to_string(),
            ));
        } else {
            let error = match serde_path_to_error::deserialize::<_, TE>(
                &mut serde_json::Deserializer::from_slice(reason),
            ) {
                Ok(error) => RequestTokenError::ServerResponse(error),
                Err(error) => RequestTokenError::Parse(error, reason.to_vec()),
            };
            return Err(error);
        }
    }

    Ok(())
}
