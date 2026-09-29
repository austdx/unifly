use reqwest::Method;
use serde_json::Value;

use super::IntegrationClient;
use crate::Error;

impl IntegrationClient {
    /// Raw controller passthrough keeps the Integration response intact and
    /// shares API-key/cloud error handling with typed Integration requests.
    /// Paths have already been validated by the controller before routing.
    pub(crate) async fn raw_request(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, Error> {
        let url = self.base_url.join(path)?;
        // Defense in depth: never let a relative join redirect the API key
        // outside this controller's Integration namespace or cloud console.
        if url.origin() != self.base_url.origin() || !url.path().starts_with(self.base_url.path()) {
            return Err(Error::UnsupportedOperation(
                "raw Integration path escapes the configured API base",
            ));
        }
        let is_delete = method == Method::DELETE;
        let mut request = self.http.request(method, url);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(self.parse_error(status, response).await);
        }
        // DELETE succeeds on any 2xx, whatever the body: `Controller::raw_delete`
        // discards the value (as `SessionClient::raw_delete` does), and decoding
        // a non-JSON body would report failure after the controller deleted.
        if is_delete {
            return Ok(Value::Null);
        }
        // Action endpoints answer 204 or an empty 200. That is success and
        // must not surface as a decode error, or callers retry an action the
        // controller already performed.
        let text = response.text().await?;
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        Self::decode_json(text)
    }
}
