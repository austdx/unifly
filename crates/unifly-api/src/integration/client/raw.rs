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
        if is_delete {
            self.handle_empty(response).await?;
            Ok(Value::Null)
        } else {
            self.handle_response(response).await
        }
    }
}
