// Shared transport configuration for building reqwest::Client instances.
//
// Both Session and Integration clients share TLS, timeout, and cookie
// settings through this module, avoiding duplicated builder logic.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use reqwest::cookie::Jar;

/// TLS verification mode (api-level mirror of core's TlsVerification).
#[derive(Debug, Clone)]
pub enum TlsMode {
    /// Use the system certificate store.
    System,
    /// Use a custom CA certificate from the given PEM file.
    CustomCa(PathBuf),
    /// Accept any certificate (for self-signed controllers).
    DangerAcceptInvalid,
}

/// Shared transport configuration for building HTTP clients.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub tls: TlsMode,
    pub timeout: Duration,
    pub cookie_jar: Option<Arc<Jar>>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            tls: TlsMode::DangerAcceptInvalid,
            timeout: Duration::from_secs(30),
            cookie_jar: None,
        }
    }
}

impl TransportConfig {
    /// Build a `reqwest::Client` from this config.
    pub fn build_client(&self) -> Result<reqwest::Client, crate::error::Error> {
        let mut builder = reqwest::Client::builder()
            .timeout(self.timeout)
            .user_agent("unifly/0.1.0");

        match &self.tls {
            TlsMode::System => {}
            TlsMode::CustomCa(path) => {
                let cert_pem = std::fs::read(path).map_err(|e| {
                    crate::error::Error::Tls(format!("failed to read CA cert: {e}"))
                })?;
                let cert = reqwest::Certificate::from_pem(&cert_pem)
                    .map_err(|e| crate::error::Error::Tls(format!("invalid CA cert: {e}")))?;
                builder = builder.add_root_certificate(cert);
            }
            TlsMode::DangerAcceptInvalid => {
                builder = builder.danger_accept_invalid_certs(true);
            }
        }

        if let Some(ref jar) = self.cookie_jar {
            builder = builder.cookie_provider(Arc::clone(jar));
        }

        builder
            .build()
            .map_err(|e| crate::error::Error::Tls(format!("failed to build HTTP client: {e}")))
    }

    /// Build a `reqwest::Client` with additional default headers and
    /// reqwest's default redirect policy.
    ///
    /// Do not use this for `X-API-KEY`: reqwest keeps custom headers on a
    /// cross-host redirect. API-key clients use `build_api_key_client`.
    pub fn build_client_with_headers(
        &self,
        headers: reqwest::header::HeaderMap,
    ) -> Result<reqwest::Client, crate::error::Error> {
        self.build_client_with_headers_and_redirect(headers, reqwest::redirect::Policy::default())
    }

    /// Build a client that sends `X-API-KEY` on every request and only
    /// follows redirects on `base_url`'s origin (and under `path_prefix`,
    /// when set). Every API-key client goes through this, so the key can
    /// never ride a redirect to another host.
    pub(crate) fn build_api_key_client(
        &self,
        api_key: &secrecy::SecretString,
        base_url: &url::Url,
        path_prefix: Option<String>,
    ) -> Result<reqwest::Client, crate::error::Error> {
        use secrecy::ExposeSecret;

        let mut key_value = reqwest::header::HeaderValue::from_str(api_key.expose_secret())
            .map_err(|e| crate::error::Error::Authentication {
                message: format!("invalid API key header value: {e}"),
            })?;
        key_value.set_sensitive(true);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("X-API-KEY", key_value);
        self.build_client_with_headers_and_redirect(
            headers,
            crate::redirect_guard::same_origin_policy(base_url, path_prefix),
        )
    }

    /// Build a client with default headers and an explicit redirect policy.
    pub(crate) fn build_client_with_headers_and_redirect(
        &self,
        headers: reqwest::header::HeaderMap,
        redirect: reqwest::redirect::Policy,
    ) -> Result<reqwest::Client, crate::error::Error> {
        let mut builder = reqwest::Client::builder()
            .timeout(self.timeout)
            .user_agent("unifly/0.1.0")
            .redirect(redirect)
            .default_headers(headers);

        match &self.tls {
            TlsMode::System => {}
            TlsMode::CustomCa(path) => {
                let cert_pem = std::fs::read(path).map_err(|e| {
                    crate::error::Error::Tls(format!("failed to read CA cert: {e}"))
                })?;
                let cert = reqwest::Certificate::from_pem(&cert_pem)
                    .map_err(|e| crate::error::Error::Tls(format!("invalid CA cert: {e}")))?;
                builder = builder.add_root_certificate(cert);
            }
            TlsMode::DangerAcceptInvalid => {
                builder = builder.danger_accept_invalid_certs(true);
            }
        }

        if let Some(ref jar) = self.cookie_jar {
            builder = builder.cookie_provider(Arc::clone(jar));
        }

        builder
            .build()
            .map_err(|e| crate::error::Error::Tls(format!("failed to build HTTP client: {e}")))
    }

    /// Create a config with a fresh cookie jar (for session auth).
    pub fn with_cookie_jar(mut self) -> Self {
        self.cookie_jar = Some(Arc::new(Jar::default()));
        self
    }
}
