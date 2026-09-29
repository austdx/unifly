use reqwest::Method;
use serde_json::Value;

use crate::controller::Controller;
use crate::controller::support::{integration_client_context, require_session};
use crate::core_error::CoreError;

/// Validate before selecting credentials: URL normalization must not change
/// the namespace after we have chosen the API-key or cookie transport.
fn relative_path(path: &str) -> Result<&str, CoreError> {
    let relative = path.strip_prefix('/').unwrap_or(path);
    let pathname = relative.split('?').next().unwrap_or_default();
    let encoded = pathname.to_ascii_lowercase();
    let invalid_segment = encoded.split('/').any(|segment| {
        let decoded = segment.replace("%2e", ".");
        decoded == "." || decoded == ".."
    });
    if pathname.is_empty()
        || relative.starts_with('/')
        || pathname
            .split('/')
            .next()
            .is_some_and(|first| first.contains(':'))
        || path.contains(['\\', '#'])
        || path.chars().any(char::is_control)
        || pathname.chars().any(char::is_whitespace)
        || crate::redirect_guard::has_ambiguous_escape(&encoded)
        || invalid_segment
    {
        return Err(CoreError::ValidationFailed {
            message: "raw API paths must be relative, without fragments or traversal".into(),
        });
    }
    Ok(relative)
}

impl Controller {
    pub(super) async fn raw_request(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, CoreError> {
        let path = relative_path(path)?;
        if let Some(path) = path.strip_prefix("integration/") {
            if path.is_empty() || path.starts_with(['/', '?']) {
                return Err(CoreError::ValidationFailed {
                    message: "Integration paths must include a relative endpoint".into(),
                });
            }
            let client = integration_client_context(self, "raw Integration API request").await?;
            return Ok(client.raw_request(method, path, body).await?);
        }

        let guard = self.inner.session_client.lock().await;
        let session = require_session(guard.as_ref())?;
        let empty = Value::Null;
        let body = body.unwrap_or(&empty);
        Ok(match method {
            Method::GET => session.raw_get(path).await?,
            Method::POST => session.raw_post(path, body).await?,
            Method::PUT => session.raw_put(path, body).await?,
            Method::PATCH => session.raw_patch(path, body).await?,
            Method::DELETE => {
                session.raw_delete(path).await?;
                Value::Null
            }
            _ => {
                return Err(CoreError::ValidationFailed {
                    message: "unsupported raw API method".into(),
                });
            }
        })
    }
}
