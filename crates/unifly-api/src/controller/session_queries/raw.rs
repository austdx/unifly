use crate::controller::Controller;
use crate::core_error::CoreError;
use reqwest::Method;

mod routing;

#[cfg(test)]
mod redirect_tests;
#[cfg(test)]
mod tests;

impl Controller {
    /// Send a raw GET request to an arbitrary path on the controller.
    ///
    /// The `path` is appended to the controller base URL + platform prefix
    /// (e.g. `/proxy/network/`). `integration/` paths use API-key auth;
    /// other paths use Session auth. A single leading slash is optional.
    /// The response is returned as raw JSON without envelope unwrapping.
    pub async fn raw_get(&self, path: &str) -> Result<serde_json::Value, CoreError> {
        self.raw_request(Method::GET, path, None).await
    }

    /// Send a raw POST request to an arbitrary path on the controller.
    pub async fn raw_post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, CoreError> {
        self.raw_request(Method::POST, path, Some(body)).await
    }

    /// Send a raw PUT request to an arbitrary path on the controller.
    pub async fn raw_put(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, CoreError> {
        self.raw_request(Method::PUT, path, Some(body)).await
    }

    /// Send a raw PATCH request to an arbitrary path on the controller.
    pub async fn raw_patch(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, CoreError> {
        self.raw_request(Method::PATCH, path, Some(body)).await
    }

    /// Send a raw DELETE request to an arbitrary path on the controller.
    pub async fn raw_delete(&self, path: &str) -> Result<(), CoreError> {
        self.raw_request(Method::DELETE, path, None).await?;
        Ok(())
    }
}
